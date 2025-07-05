//! Real-time performance monitoring
//!
//! This module provides real-time monitoring of Nym blockchain performance metrics
//! with alerting, dashboards, and metric exporters.

use crate::{PerformanceError, Result, PerformanceConfig};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Mutex, broadcast};
use prometheus::{Registry, Counter, Gauge, Histogram, HistogramOpts};
use metrics::{Key, Unit, Metadata, Recorder};
use metrics_exporter_prometheus::PrometheusBuilder;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use tracing::{info, warn, error, debug};

/// Performance monitor
pub struct Monitor {
    config: PerformanceConfig,
    metric_store: Arc<MetricStore>,
    alert_engine: Arc<AlertEngine>,
    exporters: Arc<RwLock<Vec<Box<dyn MetricExporter>>>>,
    dashboard: Arc<Dashboard>,
    event_bus: Arc<EventBus>,
    is_running: Arc<RwLock<bool>>,
}

/// Metric storage
struct MetricStore {
    metrics: Arc<RwLock<HashMap<String, MetricData>>>,
    time_series: Arc<RwLock<HashMap<String, TimeSeries>>>,
    aggregates: Arc<RwLock<HashMap<String, AggregateData>>>,
}

/// Alert engine
struct AlertEngine {
    rules: Arc<RwLock<Vec<AlertRule>>>,
    active_alerts: Arc<RwLock<HashMap<String, Alert>>>,
    notification_channels: Arc<RwLock<Vec<Box<dyn NotificationChannel>>>>,
}

/// Performance dashboard
struct Dashboard {
    widgets: Arc<RwLock<Vec<DashboardWidget>>>,
    layout: Arc<RwLock<DashboardLayout>>,
    refresh_interval: Duration,
}

/// Event bus for metric events
struct EventBus {
    sender: broadcast::Sender<MetricEvent>,
}

/// Metric data
#[derive(Debug, Clone)]
struct MetricData {
    name: String,
    value: MetricValue,
    labels: HashMap<String, String>,
    timestamp: Instant,
}

/// Metric value types
#[derive(Debug, Clone)]
enum MetricValue {
    Counter(f64),
    Gauge(f64),
    Histogram(Vec<f64>),
    Summary(SummaryData),
}

/// Time series data
#[derive(Debug, Clone)]
struct TimeSeries {
    points: VecDeque<TimeSeriesPoint>,
    max_points: usize,
    retention: Duration,
}

/// Time series point
#[derive(Debug, Clone)]
struct TimeSeriesPoint {
    timestamp: Instant,
    value: f64,
}

/// Aggregate data
#[derive(Debug, Clone)]
struct AggregateData {
    count: u64,
    sum: f64,
    min: f64,
    max: f64,
    avg: f64,
    p50: f64,
    p90: f64,
    p99: f64,
}

/// Summary data
#[derive(Debug, Clone)]
struct SummaryData {
    count: u64,
    sum: f64,
    quantiles: HashMap<f64, f64>,
}

/// Alert rule
#[derive(Debug, Clone)]
pub struct AlertRule {
    pub id: String,
    pub name: String,
    pub condition: AlertCondition,
    pub severity: AlertSeverity,
    pub actions: Vec<AlertAction>,
    pub cooldown: Duration,
}

/// Alert condition
#[derive(Debug, Clone)]
pub enum AlertCondition {
    Threshold {
        metric: String,
        operator: ThresholdOperator,
        value: f64,
        duration: Duration,
    },
    Rate {
        metric: String,
        operator: ThresholdOperator,
        value: f64,
        window: Duration,
    },
    Composite {
        conditions: Vec<AlertCondition>,
        operator: LogicalOperator,
    },
}

/// Threshold operator
#[derive(Debug, Clone, Copy)]
pub enum ThresholdOperator {
    GreaterThan,
    GreaterThanOrEqual,
    LessThan,
    LessThanOrEqual,
    Equal,
    NotEqual,
}

/// Logical operator
#[derive(Debug, Clone, Copy)]
pub enum LogicalOperator {
    And,
    Or,
    Not,
}

/// Alert severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AlertSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

/// Alert action
#[derive(Debug, Clone)]
pub enum AlertAction {
    Log,
    Email { recipients: Vec<String> },
    Webhook { url: String },
    Custom { handler: String },
}

/// Active alert
#[derive(Debug, Clone)]
pub struct Alert {
    pub rule_id: String,
    pub triggered_at: Instant,
    pub message: String,
    pub severity: AlertSeverity,
    pub metric_value: f64,
    pub acknowledged: bool,
}

/// Metric event
#[derive(Debug, Clone)]
pub enum MetricEvent {
    MetricRecorded {
        name: String,
        value: f64,
        timestamp: Instant,
    },
    AlertTriggered {
        alert: Alert,
    },
    AlertResolved {
        rule_id: String,
    },
}

/// Dashboard widget
#[derive(Debug, Clone)]
pub struct DashboardWidget {
    pub id: String,
    pub widget_type: WidgetType,
    pub title: String,
    pub metrics: Vec<String>,
    pub refresh_rate: Duration,
    pub position: WidgetPosition,
}

/// Widget type
#[derive(Debug, Clone)]
pub enum WidgetType {
    LineChart,
    BarChart,
    Gauge,
    Counter,
    Heatmap,
    Table,
    Text,
}

/// Widget position
#[derive(Debug, Clone)]
pub struct WidgetPosition {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

/// Dashboard layout
#[derive(Debug, Clone)]
pub struct DashboardLayout {
    pub rows: u32,
    pub columns: u32,
    pub widgets: Vec<DashboardWidget>,
}

/// Metric exporter trait
#[async_trait::async_trait]
pub trait MetricExporter: Send + Sync {
    async fn export(&self, metrics: &[MetricData]) -> Result<()>;
    fn name(&self) -> &str;
}

/// Notification channel trait
#[async_trait::async_trait]
pub trait NotificationChannel: Send + Sync {
    async fn send(&self, alert: &Alert) -> Result<()>;
    fn name(&self) -> &str;
}

/// Monitor statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorStats {
    pub metrics_recorded: u64,
    pub alerts_triggered: u64,
    pub alerts_resolved: u64,
    pub active_alerts: usize,
    pub uptime: Duration,
    pub last_export: Option<DateTime<Utc>>,
}

/// Prometheus exporter
struct PrometheusExporter {
    registry: Registry,
    counters: HashMap<String, Counter>,
    gauges: HashMap<String, Gauge>,
    histograms: HashMap<String, Histogram>,
}

impl Monitor {
    /// Create a new monitor
    pub fn new(config: &PerformanceConfig) -> Result<Self> {
        let metric_store = Arc::new(MetricStore::new());
        let alert_engine = Arc::new(AlertEngine::new());
        let dashboard = Arc::new(Dashboard::new(config)?);
        let (sender, _) = broadcast::channel(1000);
        let event_bus = Arc::new(EventBus { sender });

        Ok(Self {
            config: config.clone(),
            metric_store,
            alert_engine,
            exporters: Arc::new(RwLock::new(Vec::new())),
            dashboard,
            event_bus,
            is_running: Arc::new(RwLock::new(false)),
        })
    }

    /// Start monitoring
    pub async fn start(&self) -> Result<()> {
        if *self.is_running.read().await {
            return Ok(());
        }

        info!("Starting performance monitor");
        *self.is_running.write().await = true;

        // Initialize exporters
        self.initialize_exporters().await?;

        // Start alert engine
        self.alert_engine.start().await?;

        // Start metric collection
        self.start_metric_collection().await?;

        // Start dashboard if enabled
        if self.config.monitoring.enable_dashboard {
            self.dashboard.start().await?;
        }

        info!("Performance monitor started");
        Ok(())
    }

    /// Stop monitoring
    pub async fn stop(&self) -> Result<()> {
        if !*self.is_running.read().await {
            return Ok(());
        }

        info!("Stopping performance monitor");
        *self.is_running.write().await = false;

        // Stop dashboard
        self.dashboard.stop().await?;

        // Export final metrics
        self.export_metrics().await?;

        info!("Performance monitor stopped");
        Ok(())
    }

    /// Record a metric
    pub async fn record_metric(&self, name: &str, value: f64, labels: HashMap<String, String>) -> Result<()> {
        let metric_data = MetricData {
            name: name.to_string(),
            value: MetricValue::Gauge(value),
            labels,
            timestamp: Instant::now(),
        };

        // Store metric
        self.metric_store.record(metric_data.clone()).await?;

        // Check alerts
        self.alert_engine.check_metric(&metric_data).await?;

        // Emit event
        self.event_bus.emit(MetricEvent::MetricRecorded {
            name: name.to_string(),
            value,
            timestamp: Instant::now(),
        }).await;

        Ok(())
    }

    /// Record a counter
    pub async fn increment_counter(&self, name: &str, value: f64, labels: HashMap<String, String>) -> Result<()> {
        let metric_data = MetricData {
            name: name.to_string(),
            value: MetricValue::Counter(value),
            labels,
            timestamp: Instant::now(),
        };

        self.metric_store.record(metric_data).await?;
        Ok(())
    }

    /// Record a histogram
    pub async fn record_histogram(&self, name: &str, value: f64, labels: HashMap<String, String>) -> Result<()> {
        let metric_data = MetricData {
            name: name.to_string(),
            value: MetricValue::Histogram(vec![value]),
            labels,
            timestamp: Instant::now(),
        };

        self.metric_store.record(metric_data).await?;
        Ok(())
    }

    /// Add alert rule
    pub async fn add_alert_rule(&self, rule: AlertRule) -> Result<()> {
        self.alert_engine.add_rule(rule).await
    }

    /// Remove alert rule
    pub async fn remove_alert_rule(&self, rule_id: &str) -> Result<()> {
        self.alert_engine.remove_rule(rule_id).await
    }

    /// Get active alerts
    pub async fn get_active_alerts(&self) -> Vec<Alert> {
        self.alert_engine.get_active_alerts().await
    }

    /// Acknowledge alert
    pub async fn acknowledge_alert(&self, rule_id: &str) -> Result<()> {
        self.alert_engine.acknowledge_alert(rule_id).await
    }

    /// Get monitor statistics
    pub async fn get_stats(&self) -> MonitorStats {
        let uptime = if *self.is_running.read().await {
            Duration::from_secs(0) // Would track actual uptime
        } else {
            Duration::from_secs(0)
        };

        MonitorStats {
            metrics_recorded: self.metric_store.get_metric_count().await,
            alerts_triggered: self.alert_engine.get_triggered_count().await,
            alerts_resolved: self.alert_engine.get_resolved_count().await,
            active_alerts: self.alert_engine.get_active_alerts().await.len(),
            uptime,
            last_export: None,
        }
    }

    /// Subscribe to metric events
    pub fn subscribe(&self) -> broadcast::Receiver<MetricEvent> {
        self.event_bus.sender.subscribe()
    }

    /// Export metrics manually
    pub async fn export_metrics(&self) -> Result<()> {
        let metrics = self.metric_store.get_all_metrics().await;
        let exporters = self.exporters.read().await;

        for exporter in exporters.iter() {
            if let Err(e) = exporter.export(&metrics).await {
                error!("Failed to export metrics via {}: {}", exporter.name(), e);
            }
        }

        Ok(())
    }

    // Private helper methods

    async fn initialize_exporters(&self) -> Result<()> {
        let mut exporters = self.exporters.write().await;

        // Add Prometheus exporter if enabled
        if self.config.monitoring.enable_prometheus {
            let prometheus = Box::new(PrometheusExporter::new()?);
            exporters.push(prometheus);
        }

        // Add other exporters as needed

        Ok(())
    }

    async fn start_metric_collection(&self) -> Result<()> {
        let metric_store = self.metric_store.clone();
        let export_interval = Duration::from_secs(self.config.monitoring.export_interval_secs);
        let exporters = self.exporters.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(export_interval);
            loop {
                interval.tick().await;
                
                let metrics = metric_store.get_all_metrics().await;
                let exporters = exporters.read().await;
                
                for exporter in exporters.iter() {
                    if let Err(e) = exporter.export(&metrics).await {
                        warn!("Failed to export metrics: {}", e);
                    }
                }
            }
        });

        Ok(())
    }
}

impl MetricStore {
    fn new() -> Self {
        Self {
            metrics: Arc::new(RwLock::new(HashMap::new())),
            time_series: Arc::new(RwLock::new(HashMap::new())),
            aggregates: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn record(&self, metric: MetricData) -> Result<()> {
        // Store latest value
        self.metrics.write().await.insert(metric.name.clone(), metric.clone());

        // Update time series
        self.update_time_series(&metric).await?;

        // Update aggregates
        self.update_aggregates(&metric).await?;

        Ok(())
    }

    async fn update_time_series(&self, metric: &MetricData) -> Result<()> {
        let mut time_series = self.time_series.write().await;
        
        let series = time_series.entry(metric.name.clone()).or_insert_with(|| {
            TimeSeries {
                points: VecDeque::new(),
                max_points: 1000,
                retention: Duration::from_secs(3600),
            }
        });

        let value = match &metric.value {
            MetricValue::Counter(v) | MetricValue::Gauge(v) => *v,
            MetricValue::Histogram(values) => values.iter().sum::<f64>() / values.len() as f64,
            MetricValue::Summary(summary) => summary.sum / summary.count as f64,
        };

        series.points.push_back(TimeSeriesPoint {
            timestamp: metric.timestamp,
            value,
        });

        // Remove old points
        while series.points.len() > series.max_points {
            series.points.pop_front();
        }

        Ok(())
    }

    async fn update_aggregates(&self, metric: &MetricData) -> Result<()> {
        // Update aggregate statistics
        Ok(())
    }

    async fn get_all_metrics(&self) -> Vec<MetricData> {
        self.metrics.read().await.values().cloned().collect()
    }

    async fn get_metric_count(&self) -> u64 {
        self.metrics.read().await.len() as u64
    }
}

impl AlertEngine {
    fn new() -> Self {
        Self {
            rules: Arc::new(RwLock::new(Vec::new())),
            active_alerts: Arc::new(RwLock::new(HashMap::new())),
            notification_channels: Arc::new(RwLock::new(Vec::new())),
        }
    }

    async fn start(&self) -> Result<()> {
        // Initialize default alert rules
        self.initialize_default_rules().await?;
        Ok(())
    }

    async fn check_metric(&self, metric: &MetricData) -> Result<()> {
        let rules = self.rules.read().await;
        
        for rule in rules.iter() {
            if self.evaluate_condition(&rule.condition, metric).await? {
                self.trigger_alert(rule, metric).await?;
            } else {
                self.resolve_alert(&rule.id).await?;
            }
        }

        Ok(())
    }

    async fn evaluate_condition(&self, condition: &AlertCondition, metric: &MetricData) -> Result<bool> {
        match condition {
            AlertCondition::Threshold { metric: metric_name, operator, value, .. } => {
                if metric.name != *metric_name {
                    return Ok(false);
                }

                let metric_value = match &metric.value {
                    MetricValue::Counter(v) | MetricValue::Gauge(v) => *v,
                    _ => return Ok(false),
                };

                Ok(match operator {
                    ThresholdOperator::GreaterThan => metric_value > *value,
                    ThresholdOperator::GreaterThanOrEqual => metric_value >= *value,
                    ThresholdOperator::LessThan => metric_value < *value,
                    ThresholdOperator::LessThanOrEqual => metric_value <= *value,
                    ThresholdOperator::Equal => (metric_value - *value).abs() < f64::EPSILON,
                    ThresholdOperator::NotEqual => (metric_value - *value).abs() >= f64::EPSILON,
                })
            }
            _ => Ok(false), // Other conditions not implemented yet
        }
    }

    async fn trigger_alert(&self, rule: &AlertRule, metric: &MetricData) -> Result<()> {
        let mut active_alerts = self.active_alerts.write().await;
        
        if active_alerts.contains_key(&rule.id) {
            return Ok(()); // Alert already active
        }

        let metric_value = match &metric.value {
            MetricValue::Counter(v) | MetricValue::Gauge(v) => *v,
            _ => 0.0,
        };

        let alert = Alert {
            rule_id: rule.id.clone(),
            triggered_at: Instant::now(),
            message: format!("Alert: {} - {} value: {}", rule.name, metric.name, metric_value),
            severity: rule.severity,
            metric_value,
            acknowledged: false,
        };

        active_alerts.insert(rule.id.clone(), alert.clone());

        // Send notifications
        self.send_notifications(&alert).await?;

        Ok(())
    }

    async fn resolve_alert(&self, rule_id: &str) -> Result<()> {
        self.active_alerts.write().await.remove(rule_id);
        Ok(())
    }

    async fn send_notifications(&self, alert: &Alert) -> Result<()> {
        let channels = self.notification_channels.read().await;
        
        for channel in channels.iter() {
            if let Err(e) = channel.send(alert).await {
                error!("Failed to send notification via {}: {}", channel.name(), e);
            }
        }

        Ok(())
    }

    async fn add_rule(&self, rule: AlertRule) -> Result<()> {
        self.rules.write().await.push(rule);
        Ok(())
    }

    async fn remove_rule(&self, rule_id: &str) -> Result<()> {
        self.rules.write().await.retain(|r| r.id != rule_id);
        self.active_alerts.write().await.remove(rule_id);
        Ok(())
    }

    async fn get_active_alerts(&self) -> Vec<Alert> {
        self.active_alerts.read().await.values().cloned().collect()
    }

    async fn acknowledge_alert(&self, rule_id: &str) -> Result<()> {
        if let Some(alert) = self.active_alerts.write().await.get_mut(rule_id) {
            alert.acknowledged = true;
        }
        Ok(())
    }

    async fn get_triggered_count(&self) -> u64 {
        0 // Would track this
    }

    async fn get_resolved_count(&self) -> u64 {
        0 // Would track this
    }

    async fn initialize_default_rules(&self) -> Result<()> {
        // Add default performance alert rules
        let high_cpu_rule = AlertRule {
            id: "high_cpu".to_string(),
            name: "High CPU Usage".to_string(),
            condition: AlertCondition::Threshold {
                metric: "cpu_usage_percent".to_string(),
                operator: ThresholdOperator::GreaterThan,
                value: 80.0,
                duration: Duration::from_secs(300),
            },
            severity: AlertSeverity::Warning,
            actions: vec![AlertAction::Log],
            cooldown: Duration::from_secs(600),
        };

        let high_memory_rule = AlertRule {
            id: "high_memory".to_string(),
            name: "High Memory Usage".to_string(),
            condition: AlertCondition::Threshold {
                metric: "memory_usage_mb".to_string(),
                operator: ThresholdOperator::GreaterThan,
                value: 1024.0,
                duration: Duration::from_secs(300),
            },
            severity: AlertSeverity::Warning,
            actions: vec![AlertAction::Log],
            cooldown: Duration::from_secs(600),
        };

        self.add_rule(high_cpu_rule).await?;
        self.add_rule(high_memory_rule).await?;

        Ok(())
    }
}

impl Dashboard {
    fn new(config: &PerformanceConfig) -> Result<Self> {
        Ok(Self {
            widgets: Arc::new(RwLock::new(Vec::new())),
            layout: Arc::new(RwLock::new(DashboardLayout {
                rows: 4,
                columns: 6,
                widgets: Vec::new(),
            })),
            refresh_interval: Duration::from_secs(config.monitoring.dashboard_refresh_secs),
        })
    }

    async fn start(&self) -> Result<()> {
        // Initialize default widgets
        self.initialize_default_widgets().await?;
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        Ok(())
    }

    async fn initialize_default_widgets(&self) -> Result<()> {
        let mut widgets = self.widgets.write().await;

        // CPU usage widget
        widgets.push(DashboardWidget {
            id: "cpu_usage".to_string(),
            widget_type: WidgetType::LineChart,
            title: "CPU Usage".to_string(),
            metrics: vec!["cpu_usage_percent".to_string()],
            refresh_rate: Duration::from_secs(5),
            position: WidgetPosition { x: 0, y: 0, width: 2, height: 1 },
        });

        // Memory usage widget
        widgets.push(DashboardWidget {
            id: "memory_usage".to_string(),
            widget_type: WidgetType::LineChart,
            title: "Memory Usage".to_string(),
            metrics: vec!["memory_usage_mb".to_string()],
            refresh_rate: Duration::from_secs(5),
            position: WidgetPosition { x: 2, y: 0, width: 2, height: 1 },
        });

        // Transaction throughput widget
        widgets.push(DashboardWidget {
            id: "tx_throughput".to_string(),
            widget_type: WidgetType::Counter,
            title: "Transaction Throughput".to_string(),
            metrics: vec!["transactions_per_second".to_string()],
            refresh_rate: Duration::from_secs(1),
            position: WidgetPosition { x: 4, y: 0, width: 2, height: 1 },
        });

        Ok(())
    }
}

impl EventBus {
    async fn emit(&self, event: MetricEvent) {
        let _ = self.sender.send(event);
    }
}

#[async_trait::async_trait]
impl MetricExporter for PrometheusExporter {
    async fn export(&self, metrics: &[MetricData]) -> Result<()> {
        // Export metrics to Prometheus
        for metric in metrics {
            match &metric.value {
                MetricValue::Counter(value) => {
                    // Update counter
                }
                MetricValue::Gauge(value) => {
                    // Update gauge
                }
                MetricValue::Histogram(values) => {
                    // Update histogram
                }
                MetricValue::Summary(_) => {
                    // Update summary
                }
            }
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "Prometheus"
    }
}

impl PrometheusExporter {
    fn new() -> Result<Self> {
        let registry = Registry::new();
        Ok(Self {
            registry,
            counters: HashMap::new(),
            gauges: HashMap::new(),
            histograms: HashMap::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PerformanceConfig;

    #[tokio::test]
    async fn test_monitor_creation() {
        let config = PerformanceConfig::default();
        let monitor = Monitor::new(&config).unwrap();
        
        monitor.start().await.unwrap();
        
        let stats = monitor.get_stats().await;
        assert_eq!(stats.metrics_recorded, 0);
        assert_eq!(stats.active_alerts, 0);
        
        monitor.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_metric_recording() {
        let config = PerformanceConfig::default();
        let monitor = Monitor::new(&config).unwrap();
        monitor.start().await.unwrap();

        let mut labels = HashMap::new();
        labels.insert("component".to_string(), "test".to_string());

        monitor.record_metric("test_metric", 42.0, labels).await.unwrap();

        let stats = monitor.get_stats().await;
        assert!(stats.metrics_recorded > 0);

        monitor.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_alert_rules() {
        let config = PerformanceConfig::default();
        let monitor = Monitor::new(&config).unwrap();
        monitor.start().await.unwrap();

        let rule = AlertRule {
            id: "test_alert".to_string(),
            name: "Test Alert".to_string(),
            condition: AlertCondition::Threshold {
                metric: "test_metric".to_string(),
                operator: ThresholdOperator::GreaterThan,
                value: 100.0,
                duration: Duration::from_secs(0),
            },
            severity: AlertSeverity::Warning,
            actions: vec![AlertAction::Log],
            cooldown: Duration::from_secs(60),
        };

        monitor.add_alert_rule(rule).await.unwrap();

        // Trigger alert
        monitor.record_metric("test_metric", 150.0, HashMap::new()).await.unwrap();

        let alerts = monitor.get_active_alerts().await;
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id, "test_alert");

        monitor.stop().await.unwrap();
    }
}