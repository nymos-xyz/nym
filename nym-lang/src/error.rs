//! Error handling for NymScript - Week 61-62
//! 
//! This module provides comprehensive error handling for the NymScript language:
//! - Error types and severity levels
//! - Error context and location tracking
//! - Suggestion system for error recovery
//! - Error formatting and reporting

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Main error type for NymScript
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NymScriptError {
    /// Error message
    pub message: String,
    /// Error type
    pub error_type: ErrorType,
    /// Error severity
    pub severity: ErrorSeverity,
    /// Source location
    pub location: Option<SourceLocation>,
    /// Suggested fixes
    pub suggestions: Vec<String>,
    /// Additional context
    pub context: HashMap<String, String>,
}

/// Types of errors that can occur
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ErrorType {
    /// Lexical analysis errors
    Lexical,
    /// Parsing errors
    Parse,
    /// Type checking errors
    Type,
    /// Semantic analysis errors
    Semantic,
    /// Privacy violation errors
    Privacy,
    /// Security violation errors
    Security,
    /// Compiler errors
    Compiler,
    /// Runtime errors
    Runtime,
    /// I/O errors
    IO,
    /// System errors
    System,
}

/// Error severity levels
#[derive(Debug, Clone, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum ErrorSeverity {
    /// Information - not an error
    Info,
    /// Warning - potential issue
    Warning,
    /// Error - compilation/execution failure
    Error,
    /// Critical - system failure
    Critical,
}

/// Source location for error reporting
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SourceLocation {
    /// File name
    pub file: String,
    /// Line number (1-based)
    pub line: u32,
    /// Column number (1-based)
    pub column: u32,
    /// Character offset in file
    pub offset: usize,
}

/// Error context for additional information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompilerErrorContext {
    /// Context type
    pub context_type: ContextType,
    /// Context data
    pub data: HashMap<String, String>,
    /// Related locations
    pub related_locations: Vec<SourceLocation>,
}

/// Types of error contexts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ContextType {
    /// Function context
    Function,
    /// Contract context
    Contract,
    /// Type context
    Type,
    /// Privacy context
    Privacy,
    /// Security context
    Security,
    /// Expression context
    Expression,
    /// Statement context
    Statement,
}

impl NymScriptError {
    /// Create a new error
    pub fn new(
        message: String,
        error_type: ErrorType,
        severity: ErrorSeverity,
    ) -> Self {
        Self {
            message,
            error_type,
            severity,
            location: None,
            suggestions: Vec::new(),
            context: HashMap::new(),
        }
    }

    /// Create an error with location
    pub fn with_location(
        message: String,
        error_type: ErrorType,
        severity: ErrorSeverity,
        location: SourceLocation,
    ) -> Self {
        Self {
            message,
            error_type,
            severity,
            location: Some(location),
            suggestions: Vec::new(),
            context: HashMap::new(),
        }
    }

    /// Add a suggestion to the error
    pub fn with_suggestion(mut self, suggestion: String) -> Self {
        self.suggestions.push(suggestion);
        self
    }

    /// Add context to the error
    pub fn with_context(mut self, key: String, value: String) -> Self {
        self.context.insert(key, value);
        self
    }

    /// Add multiple suggestions
    pub fn with_suggestions(mut self, suggestions: Vec<String>) -> Self {
        self.suggestions.extend(suggestions);
        self
    }

    /// Create a lexical error
    pub fn lexical(message: String) -> Self {
        Self::new(message, ErrorType::Lexical, ErrorSeverity::Error)
    }

    /// Create a parse error
    pub fn parse(message: String) -> Self {
        Self::new(message, ErrorType::Parse, ErrorSeverity::Error)
    }

    /// Create a type error
    pub fn type_error(message: String) -> Self {
        Self::new(message, ErrorType::Type, ErrorSeverity::Error)
    }

    /// Create a semantic error
    pub fn semantic(message: String) -> Self {
        Self::new(message, ErrorType::Semantic, ErrorSeverity::Error)
    }

    /// Create a privacy error
    pub fn privacy(message: String) -> Self {
        Self::new(message, ErrorType::Privacy, ErrorSeverity::Error)
    }

    /// Create a security error
    pub fn security(message: String) -> Self {
        Self::new(message, ErrorType::Security, ErrorSeverity::Critical)
    }

    /// Create a compiler error
    pub fn compiler(message: String) -> Self {
        Self::new(message, ErrorType::Compiler, ErrorSeverity::Error)
    }

    /// Create a runtime error
    pub fn runtime(message: String) -> Self {
        Self::new(message, ErrorType::Runtime, ErrorSeverity::Error)
    }

    /// Create an I/O error
    pub fn io_error(message: String) -> Self {
        Self::new(message, ErrorType::IO, ErrorSeverity::Error)
    }

    /// Create a system error
    pub fn system(message: String) -> Self {
        Self::new(message, ErrorType::System, ErrorSeverity::Critical)
    }

    /// Check if error is fatal
    pub fn is_fatal(&self) -> bool {
        matches!(self.severity, ErrorSeverity::Critical) ||
        (matches!(self.error_type, ErrorType::Security) && 
         matches!(self.severity, ErrorSeverity::Error))
    }

    /// Get error code
    pub fn error_code(&self) -> String {
        match (&self.error_type, &self.severity) {
            (ErrorType::Lexical, ErrorSeverity::Error) => "E0001".to_string(),
            (ErrorType::Parse, ErrorSeverity::Error) => "E0002".to_string(),
            (ErrorType::Type, ErrorSeverity::Error) => "E0003".to_string(),
            (ErrorType::Semantic, ErrorSeverity::Error) => "E0004".to_string(),
            (ErrorType::Privacy, ErrorSeverity::Error) => "E0005".to_string(),
            (ErrorType::Security, ErrorSeverity::Error) => "E0006".to_string(),
            (ErrorType::Security, ErrorSeverity::Critical) => "E0007".to_string(),
            (ErrorType::Compiler, ErrorSeverity::Error) => "E0008".to_string(),
            (ErrorType::Runtime, ErrorSeverity::Error) => "E0009".to_string(),
            (ErrorType::IO, ErrorSeverity::Error) => "E0010".to_string(),
            (ErrorType::System, ErrorSeverity::Critical) => "E0011".to_string(),
            _ => "E0000".to_string(),
        }
    }
}

impl SourceLocation {
    /// Create a new source location
    pub fn new(file: String, line: u32, column: u32, offset: usize) -> Self {
        Self {
            file,
            line,
            column,
            offset,
        }
    }

    /// Create a location from line and column
    pub fn from_line_col(file: String, line: u32, column: u32) -> Self {
        Self {
            file,
            line,
            column,
            offset: 0, // Would need source text to calculate
        }
    }
}

impl fmt::Display for NymScriptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Error code and severity
        write!(f, "{} [{}]: ", self.error_code(), self.severity)?;
        
        // Main message
        writeln!(f, "{}", self.message)?;
        
        // Location information
        if let Some(location) = &self.location {
            writeln!(f, "  --> {}:{}:{}", location.file, location.line, location.column)?;
        }
        
        // Context information
        if !self.context.is_empty() {
            writeln!(f, "Context:")?;
            for (key, value) in &self.context {
                writeln!(f, "  {}: {}", key, value)?;
            }
        }
        
        // Suggestions
        if !self.suggestions.is_empty() {
            writeln!(f, "Suggestions:")?;
            for suggestion in &self.suggestions {
                writeln!(f, "  - {}", suggestion)?;
            }
        }
        
        Ok(())
    }
}

impl fmt::Display for ErrorSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorSeverity::Info => write!(f, "INFO"),
            ErrorSeverity::Warning => write!(f, "WARNING"),
            ErrorSeverity::Error => write!(f, "ERROR"),
            ErrorSeverity::Critical => write!(f, "CRITICAL"),
        }
    }
}

impl fmt::Display for ErrorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorType::Lexical => write!(f, "Lexical"),
            ErrorType::Parse => write!(f, "Parse"),
            ErrorType::Type => write!(f, "Type"),
            ErrorType::Semantic => write!(f, "Semantic"),
            ErrorType::Privacy => write!(f, "Privacy"),
            ErrorType::Security => write!(f, "Security"),
            ErrorType::Compiler => write!(f, "Compiler"),
            ErrorType::Runtime => write!(f, "Runtime"),
            ErrorType::IO => write!(f, "IO"),
            ErrorType::System => write!(f, "System"),
        }
    }
}

impl std::error::Error for NymScriptError {}

impl From<std::io::Error> for NymScriptError {
    fn from(error: std::io::Error) -> Self {
        Self::io_error(format!("I/O error: {}", error))
    }
}

impl From<serde_json::Error> for NymScriptError {
    fn from(error: serde_json::Error) -> Self {
        Self::compiler(format!("JSON serialization error: {}", error))
    }
}

/// Error collection for multiple errors
#[derive(Debug, Clone)]
pub struct ErrorCollection {
    /// All errors
    pub errors: Vec<NymScriptError>,
    /// Warnings
    pub warnings: Vec<NymScriptError>,
}

impl ErrorCollection {
    /// Create a new error collection
    pub fn new() -> Self {
        Self {
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// Add an error
    pub fn add_error(&mut self, error: NymScriptError) {
        match error.severity {
            ErrorSeverity::Warning => self.warnings.push(error),
            _ => self.errors.push(error),
        }
    }

    /// Add multiple errors
    pub fn add_errors(&mut self, errors: Vec<NymScriptError>) {
        for error in errors {
            self.add_error(error);
        }
    }

    /// Check if there are any errors
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    /// Check if there are any warnings
    pub fn has_warnings(&self) -> bool {
        !self.warnings.is_empty()
    }

    /// Get total count
    pub fn total_count(&self) -> usize {
        self.errors.len() + self.warnings.len()
    }

    /// Get fatal errors
    pub fn fatal_errors(&self) -> Vec<&NymScriptError> {
        self.errors.iter().filter(|e| e.is_fatal()).collect()
    }

    /// Sort errors by location
    pub fn sort_by_location(&mut self) {
        self.errors.sort_by(|a, b| {
            match (&a.location, &b.location) {
                (Some(loc_a), Some(loc_b)) => {
                    loc_a.file.cmp(&loc_b.file)
                        .then(loc_a.line.cmp(&loc_b.line))
                        .then(loc_a.column.cmp(&loc_b.column))
                }
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => std::cmp::Ordering::Equal,
            }
        });
        
        self.warnings.sort_by(|a, b| {
            match (&a.location, &b.location) {
                (Some(loc_a), Some(loc_b)) => {
                    loc_a.file.cmp(&loc_b.file)
                        .then(loc_a.line.cmp(&loc_b.line))
                        .then(loc_a.column.cmp(&loc_b.column))
                }
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => std::cmp::Ordering::Equal,
            }
        });
    }

    /// Format all errors
    pub fn format_all(&self) -> String {
        let mut output = String::new();
        
        if !self.errors.is_empty() {
            output.push_str("Errors:\n");
            for error in &self.errors {
                output.push_str(&format!("{}\n", error));
            }
        }
        
        if !self.warnings.is_empty() {
            output.push_str("Warnings:\n");
            for warning in &self.warnings {
                output.push_str(&format!("{}\n", warning));
            }
        }
        
        output
    }
}

impl Default for ErrorCollection {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ErrorCollection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.format_all())
    }
}

/// Error reporter for formatting and displaying errors
pub struct ErrorReporter {
    /// Show line numbers
    pub show_line_numbers: bool,
    /// Show suggestions
    pub show_suggestions: bool,
    /// Show context
    pub show_context: bool,
    /// Color output
    pub use_colors: bool,
    /// Maximum context lines
    pub max_context_lines: usize,
}

impl ErrorReporter {
    /// Create a new error reporter
    pub fn new() -> Self {
        Self {
            show_line_numbers: true,
            show_suggestions: true,
            show_context: true,
            use_colors: true,
            max_context_lines: 3,
        }
    }

    /// Create a minimal reporter
    pub fn minimal() -> Self {
        Self {
            show_line_numbers: false,
            show_suggestions: false,
            show_context: false,
            use_colors: false,
            max_context_lines: 0,
        }
    }

    /// Report a single error
    pub fn report_error(&self, error: &NymScriptError) -> String {
        let mut output = String::new();
        
        // Error header
        if self.use_colors {
            output.push_str(&format!(
                "\x1b[1;31m{} [{}]\x1b[0m: {}\n",
                error.error_code(),
                error.severity,
                error.message
            ));
        } else {
            output.push_str(&format!(
                "{} [{}]: {}\n",
                error.error_code(),
                error.severity,
                error.message
            ));
        }
        
        // Location
        if let Some(location) = &error.location {
            if self.use_colors {
                output.push_str(&format!(
                    "  \x1b[1;34m-->\x1b[0m {}:{}:{}\n",
                    location.file,
                    location.line,
                    location.column
                ));
            } else {
                output.push_str(&format!(
                    "  --> {}:{}:{}\n",
                    location.file,
                    location.line,
                    location.column
                ));
            }
        }
        
        // Context
        if self.show_context && !error.context.is_empty() {
            output.push_str("Context:\n");
            for (key, value) in &error.context {
                output.push_str(&format!("  {}: {}\n", key, value));
            }
        }
        
        // Suggestions
        if self.show_suggestions && !error.suggestions.is_empty() {
            if self.use_colors {
                output.push_str("\x1b[1;33mSuggestions:\x1b[0m\n");
            } else {
                output.push_str("Suggestions:\n");
            }
            for suggestion in &error.suggestions {
                output.push_str(&format!("  - {}\n", suggestion));
            }
        }
        
        output
    }

    /// Report an error collection
    pub fn report_collection(&self, collection: &ErrorCollection) -> String {
        let mut output = String::new();
        
        // Summary
        if collection.has_errors() || collection.has_warnings() {
            output.push_str(&format!(
                "Found {} error(s) and {} warning(s)\n\n",
                collection.errors.len(),
                collection.warnings.len()
            ));
        }
        
        // Errors
        for error in &collection.errors {
            output.push_str(&self.report_error(error));
            output.push('\n');
        }
        
        // Warnings
        for warning in &collection.warnings {
            output.push_str(&self.report_error(warning));
            output.push('\n');
        }
        
        output
    }
}

impl Default for ErrorReporter {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper trait for adding error context
pub trait ErrorContext<T> {
    /// Add context to an error result
    fn with_error_context(self, context: &str) -> Result<T, NymScriptError>;
}

impl<T, E> ErrorContext<T> for Result<T, E>
where
    E: Into<NymScriptError>,
{
    fn with_error_context(self, context: &str) -> Result<T, NymScriptError> {
        self.map_err(|e| {
            let mut error: NymScriptError = e.into();
            error.context.insert("context".to_string(), context.to_string());
            error
        })
    }
}

/// Macro for creating errors with location
#[macro_export]
macro_rules! error_at {
    ($error_type:expr, $severity:expr, $file:expr, $line:expr, $col:expr, $msg:expr) => {
        NymScriptError::with_location(
            $msg.to_string(),
            $error_type,
            $severity,
            SourceLocation::new($file.to_string(), $line, $col, 0),
        )
    };
}

/// Macro for creating errors with suggestions
#[macro_export]
macro_rules! error_with_suggestion {
    ($error_type:expr, $severity:expr, $msg:expr, $suggestion:expr) => {
        NymScriptError::new($msg.to_string(), $error_type, $severity)
            .with_suggestion($suggestion.to_string())
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let error = NymScriptError::new(
            "Test error".to_string(),
            ErrorType::Type,
            ErrorSeverity::Error,
        );
        
        assert_eq!(error.message, "Test error");
        assert_eq!(error.error_type, ErrorType::Type);
        assert_eq!(error.severity, ErrorSeverity::Error);
        assert!(error.location.is_none());
        assert!(error.suggestions.is_empty());
    }

    #[test]
    fn test_error_with_location() {
        let location = SourceLocation::new("test.nys".to_string(), 10, 5, 100);
        let error = NymScriptError::with_location(
            "Parse error".to_string(),
            ErrorType::Parse,
            ErrorSeverity::Error,
            location.clone(),
        );
        
        assert_eq!(error.location, Some(location));
    }

    #[test]
    fn test_error_with_suggestions() {
        let error = NymScriptError::type_error("Type mismatch".to_string())
            .with_suggestion("Try converting the type".to_string())
            .with_suggestion("Check the variable declaration".to_string());
        
        assert_eq!(error.suggestions.len(), 2);
        assert_eq!(error.suggestions[0], "Try converting the type");
    }

    #[test]
    fn test_error_codes() {
        let lexical_error = NymScriptError::lexical("Invalid token".to_string());
        assert_eq!(lexical_error.error_code(), "E0001");
        
        let parse_error = NymScriptError::parse("Unexpected token".to_string());
        assert_eq!(parse_error.error_code(), "E0002");
        
        let type_error = NymScriptError::type_error("Type mismatch".to_string());
        assert_eq!(type_error.error_code(), "E0003");
    }

    #[test]
    fn test_error_fatality() {
        let error = NymScriptError::new(
            "Regular error".to_string(),
            ErrorType::Type,
            ErrorSeverity::Error,
        );
        assert!(!error.is_fatal());
        
        let critical_error = NymScriptError::new(
            "Critical error".to_string(),
            ErrorType::System,
            ErrorSeverity::Critical,
        );
        assert!(critical_error.is_fatal());
        
        let security_error = NymScriptError::security("Security violation".to_string());
        assert!(security_error.is_fatal());
    }

    #[test]
    fn test_error_collection() {
        let mut collection = ErrorCollection::new();
        
        assert!(!collection.has_errors());
        assert!(!collection.has_warnings());
        assert_eq!(collection.total_count(), 0);
        
        collection.add_error(NymScriptError::type_error("Type error".to_string()));
        collection.add_error(NymScriptError::new(
            "Warning".to_string(),
            ErrorType::Semantic,
            ErrorSeverity::Warning,
        ));
        
        assert!(collection.has_errors());
        assert!(collection.has_warnings());
        assert_eq!(collection.total_count(), 2);
        assert_eq!(collection.errors.len(), 1);
        assert_eq!(collection.warnings.len(), 1);
    }

    #[test]
    fn test_error_sorting() {
        let mut collection = ErrorCollection::new();
        
        let error1 = NymScriptError::with_location(
            "Error 1".to_string(),
            ErrorType::Type,
            ErrorSeverity::Error,
            SourceLocation::new("file1.nys".to_string(), 20, 5, 0),
        );
        
        let error2 = NymScriptError::with_location(
            "Error 2".to_string(),
            ErrorType::Parse,
            ErrorSeverity::Error,
            SourceLocation::new("file1.nys".to_string(), 10, 3, 0),
        );
        
        collection.add_error(error1);
        collection.add_error(error2);
        
        collection.sort_by_location();
        
        // Should be sorted by line number
        assert_eq!(collection.errors[0].location.as_ref().unwrap().line, 10);
        assert_eq!(collection.errors[1].location.as_ref().unwrap().line, 20);
    }

    #[test]
    fn test_error_display() {
        let error = NymScriptError::with_location(
            "Test error message".to_string(),
            ErrorType::Type,
            ErrorSeverity::Error,
            SourceLocation::new("test.nys".to_string(), 5, 10, 50),
        )
        .with_suggestion("Try fixing this")
        .with_context("function".to_string(), "test_function".to_string());
        
        let display = format!("{}", error);
        
        assert!(display.contains("E0003"));
        assert!(display.contains("Test error message"));
        assert!(display.contains("test.nys:5:10"));
        assert!(display.contains("Try fixing this"));
        assert!(display.contains("function: test_function"));
    }

    #[test]
    fn test_error_reporter() {
        let reporter = ErrorReporter::new();
        let error = NymScriptError::type_error("Type mismatch".to_string())
            .with_suggestion("Check variable type");
        
        let report = reporter.report_error(&error);
        
        assert!(report.contains("E0003"));
        assert!(report.contains("Type mismatch"));
        assert!(report.contains("Check variable type"));
    }

    #[test]
    fn test_minimal_reporter() {
        let reporter = ErrorReporter::minimal();
        let error = NymScriptError::type_error("Type mismatch".to_string())
            .with_suggestion("Check variable type");
        
        let report = reporter.report_error(&error);
        
        // Should not contain suggestions or colors
        assert!(report.contains("Type mismatch"));
        assert!(!report.contains("Suggestions:"));
        assert!(!report.contains("\x1b["));
    }

    #[test]
    fn test_source_location() {
        let location = SourceLocation::new("test.nys".to_string(), 10, 5, 100);
        
        assert_eq!(location.file, "test.nys");
        assert_eq!(location.line, 10);
        assert_eq!(location.column, 5);
        assert_eq!(location.offset, 100);
        
        let location2 = SourceLocation::from_line_col("test2.nys".to_string(), 20, 15);
        assert_eq!(location2.file, "test2.nys");
        assert_eq!(location2.line, 20);
        assert_eq!(location2.column, 15);
        assert_eq!(location2.offset, 0);
    }

    #[test]
    fn test_error_context_trait() {
        use std::num::ParseIntError;
        
        let result: Result<i32, ParseIntError> = "not_a_number".parse();
        let error_result: Result<i32, NymScriptError> = result
            .map_err(|_| NymScriptError::parse("Parse failed".to_string()))
            .with_error_context("parsing integer");
        
        assert!(error_result.is_err());
        let error = error_result.unwrap_err();
        assert!(error.context.contains_key("context"));
        assert_eq!(error.context["context"], "parsing integer");
    }
}