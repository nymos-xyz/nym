//! Custom memory allocators for performance optimization
//!
//! This module provides specialized memory allocators optimized for
//! different use cases in the Nym blockchain.

use crate::{PerformanceError, Result};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::UnsafeCell;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use bumpalo::Bump;
use parking_lot::RwLock;
use slotmap::{SlotMap, DefaultKey};
use smallvec::SmallVec;
use tracing::{debug, trace};

/// Arena allocator for short-lived allocations
pub struct ArenaAllocator {
    arenas: Arc<RwLock<Vec<Bump>>>,
    current_arena: Arc<RwLock<usize>>,
    arena_size: usize,
    total_allocated: AtomicUsize,
}

/// Pool allocator for fixed-size allocations
pub struct PoolAllocator<T> {
    pools: Arc<RwLock<HashMap<usize, ObjectPool<T>>>>,
    size_classes: Vec<usize>,
    max_pool_size: usize,
}

/// Slab allocator for efficient allocation/deallocation
pub struct SlabAllocator {
    slabs: Arc<RwLock<SlotMap<DefaultKey, SlabEntry>>>,
    free_list: Arc<RwLock<Vec<DefaultKey>>>,
    slab_size: usize,
    total_slabs: AtomicUsize,
}

/// Stack allocator for LIFO allocations
pub struct StackAllocator {
    stack: Arc<Mutex<Vec<u8>>>,
    top: AtomicUsize,
    capacity: usize,
}

/// Ring buffer allocator for cyclic allocations
pub struct RingAllocator {
    buffer: Arc<UnsafeCell<Vec<u8>>>,
    head: AtomicUsize,
    tail: AtomicUsize,
    capacity: usize,
}

/// Object pool for recycling allocations
struct ObjectPool<T> {
    available: Vec<T>,
    in_use: HashMap<usize, T>,
    max_size: usize,
}

/// Slab entry
struct SlabEntry {
    data: Vec<u8>,
    size: usize,
    allocated: bool,
}

/// Allocation statistics
#[derive(Debug, Clone, Default)]
pub struct AllocationStats {
    pub total_allocations: u64,
    pub total_deallocations: u64,
    pub current_allocated: usize,
    pub peak_allocated: usize,
    pub allocation_failures: u64,
    pub fragmentation_ratio: f64,
}

/// Memory region for custom allocators
pub struct MemoryRegion {
    ptr: NonNull<u8>,
    layout: Layout,
    allocator_type: AllocatorType,
}

/// Allocator type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocatorType {
    Arena,
    Pool,
    Slab,
    Stack,
    Ring,
    System,
}

/// Allocator manager
pub struct AllocatorManager {
    arena: Arc<ArenaAllocator>,
    slab: Arc<SlabAllocator>,
    stack: Arc<StackAllocator>,
    ring: Arc<RingAllocator>,
    stats: Arc<RwLock<AllocationStats>>,
    regions: Arc<RwLock<HashMap<usize, MemoryRegion>>>,
}

impl ArenaAllocator {
    /// Create a new arena allocator
    pub fn new(arena_size: usize) -> Self {
        let initial_arena = Bump::with_capacity(arena_size);
        let arenas = vec![initial_arena];
        
        Self {
            arenas: Arc::new(RwLock::new(arenas)),
            current_arena: Arc::new(RwLock::new(0)),
            arena_size,
            total_allocated: AtomicUsize::new(0),
        }
    }

    /// Allocate memory from the arena
    pub fn alloc(&self, layout: Layout) -> Result<NonNull<u8>> {
        let mut arenas = self.arenas.write();
        let current_idx = *self.current_arena.read();
        
        // Try to allocate from current arena
        if let Some(arena) = arenas.get_mut(current_idx) {
            if let Ok(ptr) = arena.try_alloc_layout(layout) {
                self.total_allocated.fetch_add(layout.size(), Ordering::Relaxed);
                return Ok(ptr);
            }
        }
        
        // Current arena is full, create a new one
        let new_arena = Bump::with_capacity(self.arena_size.max(layout.size()));
        let ptr = new_arena.alloc_layout(layout);
        
        arenas.push(new_arena);
        *self.current_arena.write() = arenas.len() - 1;
        
        self.total_allocated.fetch_add(layout.size(), Ordering::Relaxed);
        Ok(ptr)
    }

    /// Reset all arenas
    pub fn reset(&self) {
        let mut arenas = self.arenas.write();
        for arena in arenas.iter_mut() {
            arena.reset();
        }
        *self.current_arena.write() = 0;
        self.total_allocated.store(0, Ordering::Relaxed);
        
        debug!("Arena allocator reset");
    }

    /// Get total allocated bytes
    pub fn allocated_bytes(&self) -> usize {
        self.total_allocated.load(Ordering::Relaxed)
    }
}

impl<T: Default + Clone> PoolAllocator<T> {
    /// Create a new pool allocator
    pub fn new(size_classes: Vec<usize>, max_pool_size: usize) -> Self {
        Self {
            pools: Arc::new(RwLock::new(HashMap::new())),
            size_classes,
            max_pool_size,
        }
    }

    /// Allocate an object from the pool
    pub fn alloc(&self, size: usize) -> Result<T> {
        let size_class = self.get_size_class(size);
        let mut pools = self.pools.write();
        
        let pool = pools.entry(size_class).or_insert_with(|| {
            ObjectPool::new(self.max_pool_size)
        });
        
        pool.acquire()
    }

    /// Return an object to the pool
    pub fn dealloc(&self, obj: T, size: usize) -> Result<()> {
        let size_class = self.get_size_class(size);
        let mut pools = self.pools.write();
        
        if let Some(pool) = pools.get_mut(&size_class) {
            pool.release(obj)?;
        }
        
        Ok(())
    }

    /// Get the appropriate size class for a given size
    fn get_size_class(&self, size: usize) -> usize {
        for &class in &self.size_classes {
            if size <= class {
                return class;
            }
        }
        size.next_power_of_two()
    }

    /// Clear all pools
    pub fn clear(&self) {
        self.pools.write().clear();
        debug!("Pool allocator cleared");
    }
}

impl SlabAllocator {
    /// Create a new slab allocator
    pub fn new(slab_size: usize) -> Self {
        Self {
            slabs: Arc::new(RwLock::new(SlotMap::new())),
            free_list: Arc::new(RwLock::new(Vec::new())),
            slab_size,
            total_slabs: AtomicUsize::new(0),
        }
    }

    /// Allocate a slab
    pub fn alloc(&self, size: usize) -> Result<(DefaultKey, NonNull<u8>)> {
        if size > self.slab_size {
            return Err(PerformanceError::allocation(
                format!("Requested size {} exceeds slab size {}", size, self.slab_size)
            ));
        }

        let mut slabs = self.slabs.write();
        let mut free_list = self.free_list.write();
        
        // Check free list first
        if let Some(key) = free_list.pop() {
            if let Some(slab) = slabs.get_mut(key) {
                slab.allocated = true;
                let ptr = NonNull::new(slab.data.as_mut_ptr())
                    .ok_or_else(|| PerformanceError::allocation("Invalid slab pointer".to_string()))?;
                return Ok((key, ptr));
            }
        }
        
        // Allocate new slab
        let slab = SlabEntry {
            data: vec![0u8; self.slab_size],
            size,
            allocated: true,
        };
        
        let ptr = NonNull::new(slab.data.as_ptr() as *mut u8)
            .ok_or_else(|| PerformanceError::allocation("Failed to create slab pointer".to_string()))?;
        
        let key = slabs.insert(slab);
        self.total_slabs.fetch_add(1, Ordering::Relaxed);
        
        Ok((key, ptr))
    }

    /// Deallocate a slab
    pub fn dealloc(&self, key: DefaultKey) -> Result<()> {
        let mut slabs = self.slabs.write();
        let mut free_list = self.free_list.write();
        
        if let Some(slab) = slabs.get_mut(key) {
            slab.allocated = false;
            free_list.push(key);
            trace!("Slab deallocated: {:?}", key);
        } else {
            return Err(PerformanceError::allocation("Invalid slab key".to_string()));
        }
        
        Ok(())
    }

    /// Get total slab count
    pub fn slab_count(&self) -> usize {
        self.total_slabs.load(Ordering::Relaxed)
    }

    /// Get fragmentation ratio
    pub fn fragmentation_ratio(&self) -> f64 {
        let slabs = self.slabs.read();
        let total = slabs.len();
        if total == 0 {
            return 0.0;
        }
        
        let allocated = slabs.values().filter(|s| s.allocated).count();
        1.0 - (allocated as f64 / total as f64)
    }
}

impl StackAllocator {
    /// Create a new stack allocator
    pub fn new(capacity: usize) -> Self {
        Self {
            stack: Arc::new(Mutex::new(Vec::with_capacity(capacity))),
            top: AtomicUsize::new(0),
            capacity,
        }
    }

    /// Allocate from the stack
    pub fn alloc(&self, size: usize) -> Result<NonNull<u8>> {
        let mut stack = self.stack.lock().unwrap();
        let current_top = self.top.load(Ordering::Relaxed);
        
        if current_top + size > self.capacity {
            return Err(PerformanceError::allocation("Stack allocator full".to_string()));
        }
        
        // Ensure stack has enough space
        if stack.len() < current_top + size {
            stack.resize(current_top + size, 0);
        }
        
        let ptr = unsafe { stack.as_mut_ptr().add(current_top) };
        self.top.store(current_top + size, Ordering::Relaxed);
        
        NonNull::new(ptr)
            .ok_or_else(|| PerformanceError::allocation("Failed to create stack pointer".to_string()))
    }

    /// Reset the stack to a marker
    pub fn reset_to(&self, marker: usize) -> Result<()> {
        let current_top = self.top.load(Ordering::Relaxed);
        if marker > current_top {
            return Err(PerformanceError::allocation("Invalid stack marker".to_string()));
        }
        
        self.top.store(marker, Ordering::Relaxed);
        debug!("Stack allocator reset to marker: {}", marker);
        Ok(())
    }

    /// Get current stack position
    pub fn current_position(&self) -> usize {
        self.top.load(Ordering::Relaxed)
    }

    /// Reset the entire stack
    pub fn reset(&self) {
        self.top.store(0, Ordering::Relaxed);
        debug!("Stack allocator reset");
    }
}

impl RingAllocator {
    /// Create a new ring allocator
    pub fn new(capacity: usize) -> Self {
        let buffer = vec![0u8; capacity];
        
        Self {
            buffer: Arc::new(UnsafeCell::new(buffer)),
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            capacity,
        }
    }

    /// Allocate from the ring buffer
    pub fn alloc(&self, size: usize) -> Result<NonNull<u8>> {
        if size > self.capacity {
            return Err(PerformanceError::allocation(
                format!("Requested size {} exceeds ring capacity {}", size, self.capacity)
            ));
        }

        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        
        // Calculate available space
        let available = if head >= tail {
            self.capacity - head + tail
        } else {
            tail - head
        };
        
        if size > available {
            return Err(PerformanceError::allocation("Ring allocator full".to_string()));
        }
        
        // Allocate at head position
        let ptr = unsafe {
            let buffer = &*self.buffer.get();
            buffer.as_ptr().add(head)
        };
        
        // Update head position
        let new_head = (head + size) % self.capacity;
        self.head.store(new_head, Ordering::Release);
        
        NonNull::new(ptr as *mut u8)
            .ok_or_else(|| PerformanceError::allocation("Failed to create ring pointer".to_string()))
    }

    /// Free space in the ring buffer
    pub fn free(&self, size: usize) -> Result<()> {
        let tail = self.tail.load(Ordering::Acquire);
        let new_tail = (tail + size) % self.capacity;
        self.tail.store(new_tail, Ordering::Release);
        
        trace!("Ring allocator freed {} bytes", size);
        Ok(())
    }

    /// Reset the ring buffer
    pub fn reset(&self) {
        self.head.store(0, Ordering::Release);
        self.tail.store(0, Ordering::Release);
        debug!("Ring allocator reset");
    }
}

impl<T: Default + Clone> ObjectPool<T> {
    fn new(max_size: usize) -> Self {
        Self {
            available: Vec::with_capacity(max_size),
            in_use: HashMap::new(),
            max_size,
        }
    }

    fn acquire(&mut self) -> Result<T> {
        if let Some(obj) = self.available.pop() {
            Ok(obj)
        } else if self.in_use.len() < self.max_size {
            Ok(T::default())
        } else {
            Err(PerformanceError::allocation("Object pool exhausted".to_string()))
        }
    }

    fn release(&mut self, obj: T) -> Result<()> {
        if self.available.len() < self.max_size {
            self.available.push(obj);
            Ok(())
        } else {
            Err(PerformanceError::allocation("Object pool full".to_string()))
        }
    }
}

impl AllocatorManager {
    /// Create a new allocator manager
    pub fn new() -> Result<Self> {
        let arena = Arc::new(ArenaAllocator::new(1024 * 1024)); // 1MB arenas
        let slab = Arc::new(SlabAllocator::new(4096)); // 4KB slabs
        let stack = Arc::new(StackAllocator::new(1024 * 1024)); // 1MB stack
        let ring = Arc::new(RingAllocator::new(1024 * 1024)); // 1MB ring

        Ok(Self {
            arena,
            slab,
            stack,
            ring,
            stats: Arc::new(RwLock::new(AllocationStats::default())),
            regions: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Allocate memory using the most appropriate allocator
    pub fn alloc(&self, layout: Layout, allocator_type: AllocatorType) -> Result<NonNull<u8>> {
        let ptr = match allocator_type {
            AllocatorType::Arena => self.arena.alloc(layout)?,
            AllocatorType::Slab => {
                let (key, ptr) = self.slab.alloc(layout.size())?;
                // Store slab key for deallocation
                ptr
            }
            AllocatorType::Stack => self.stack.alloc(layout.size())?,
            AllocatorType::Ring => self.ring.alloc(layout.size())?,
            AllocatorType::Pool => {
                return Err(PerformanceError::allocation("Pool allocator requires type parameter".to_string()));
            }
            AllocatorType::System => {
                let ptr = unsafe { System.alloc(layout) };
                NonNull::new(ptr)
                    .ok_or_else(|| PerformanceError::allocation("System allocation failed".to_string()))?
            }
        };

        // Track allocation
        let region = MemoryRegion {
            ptr,
            layout,
            allocator_type,
        };
        
        self.regions.write().insert(ptr.as_ptr() as usize, region);
        self.update_stats_alloc(layout.size());

        Ok(ptr)
    }

    /// Deallocate memory
    pub fn dealloc(&self, ptr: NonNull<u8>, layout: Layout) -> Result<()> {
        let regions = self.regions.read();
        let addr = ptr.as_ptr() as usize;
        
        if let Some(region) = regions.get(&addr) {
            match region.allocator_type {
                AllocatorType::Arena => {
                    // Arena allocations are not individually freed
                }
                AllocatorType::Slab => {
                    // Would need to track slab keys
                }
                AllocatorType::Stack => {
                    // Stack allocations are freed in LIFO order
                }
                AllocatorType::Ring => {
                    self.ring.free(layout.size())?;
                }
                AllocatorType::Pool => {
                    // Pool allocations require type information
                }
                AllocatorType::System => {
                    unsafe { System.dealloc(ptr.as_ptr(), layout); }
                }
            }
        }
        
        drop(regions);
        self.regions.write().remove(&addr);
        self.update_stats_dealloc(layout.size());

        Ok(())
    }

    /// Get allocation statistics
    pub fn get_stats(&self) -> AllocationStats {
        let mut stats = self.stats.read().clone();
        stats.fragmentation_ratio = self.slab.fragmentation_ratio();
        stats
    }

    /// Reset all allocators
    pub fn reset(&self) {
        self.arena.reset();
        self.stack.reset();
        self.ring.reset();
        self.regions.write().clear();
        *self.stats.write() = AllocationStats::default();
        
        info!("All allocators reset");
    }

    /// Choose the best allocator for a given allocation pattern
    pub fn suggest_allocator(&self, size: usize, lifetime: AllocationLifetime) -> AllocatorType {
        match lifetime {
            AllocationLifetime::Temporary => {
                if size < 1024 {
                    AllocatorType::Stack
                } else {
                    AllocatorType::Arena
                }
            }
            AllocationLifetime::Short => AllocatorType::Arena,
            AllocationLifetime::Medium => {
                if size <= 4096 {
                    AllocatorType::Slab
                } else {
                    AllocatorType::System
                }
            }
            AllocationLifetime::Long => AllocatorType::System,
            AllocationLifetime::Cyclic => AllocatorType::Ring,
        }
    }

    fn update_stats_alloc(&self, size: usize) {
        let mut stats = self.stats.write();
        stats.total_allocations += 1;
        stats.current_allocated += size;
        if stats.current_allocated > stats.peak_allocated {
            stats.peak_allocated = stats.current_allocated;
        }
    }

    fn update_stats_dealloc(&self, size: usize) {
        let mut stats = self.stats.write();
        stats.total_deallocations += 1;
        stats.current_allocated = stats.current_allocated.saturating_sub(size);
    }
}

/// Allocation lifetime hint
#[derive(Debug, Clone, Copy)]
pub enum AllocationLifetime {
    Temporary,  // Very short-lived (< 1ms)
    Short,      // Short-lived (< 1s)
    Medium,     // Medium-lived (< 1min)
    Long,       // Long-lived (> 1min)
    Cyclic,     // Cyclic pattern
}

impl Default for AllocatorManager {
    fn default() -> Self {
        Self::new().expect("Failed to create default AllocatorManager")
    }
}

use tracing::info;

#[cfg(test)]
mod tests {
    use super::*;
    use std::alloc::Layout;

    #[test]
    fn test_arena_allocator() {
        let arena = ArenaAllocator::new(1024);
        let layout = Layout::from_size_align(64, 8).unwrap();
        
        let ptr1 = arena.alloc(layout).unwrap();
        let ptr2 = arena.alloc(layout).unwrap();
        
        assert_ne!(ptr1, ptr2);
        assert_eq!(arena.allocated_bytes(), 128);
        
        arena.reset();
        assert_eq!(arena.allocated_bytes(), 0);
    }

    #[test]
    fn test_slab_allocator() {
        let slab = SlabAllocator::new(256);
        
        let (key1, ptr1) = slab.alloc(128).unwrap();
        let (key2, ptr2) = slab.alloc(128).unwrap();
        
        assert_ne!(ptr1, ptr2);
        assert_eq!(slab.slab_count(), 2);
        
        slab.dealloc(key1).unwrap();
        assert!(slab.fragmentation_ratio() > 0.0);
    }

    #[test]
    fn test_stack_allocator() {
        let stack = StackAllocator::new(1024);
        
        let marker = stack.current_position();
        let ptr1 = stack.alloc(64).unwrap();
        let ptr2 = stack.alloc(64).unwrap();
        
        assert_eq!(stack.current_position(), marker + 128);
        
        stack.reset_to(marker).unwrap();
        assert_eq!(stack.current_position(), marker);
    }

    #[test]
    fn test_ring_allocator() {
        let ring = RingAllocator::new(256);
        
        let ptr1 = ring.alloc(64).unwrap();
        let ptr2 = ring.alloc(64).unwrap();
        
        assert_ne!(ptr1, ptr2);
        
        ring.free(64).unwrap();
        ring.free(64).unwrap();
        
        // Should be able to allocate again
        let ptr3 = ring.alloc(128).unwrap();
        assert!(!ptr3.as_ptr().is_null());
    }

    #[test]
    fn test_allocator_manager() {
        let manager = AllocatorManager::new().unwrap();
        let layout = Layout::from_size_align(64, 8).unwrap();
        
        let ptr1 = manager.alloc(layout, AllocatorType::Arena).unwrap();
        let ptr2 = manager.alloc(layout, AllocatorType::Stack).unwrap();
        
        assert_ne!(ptr1, ptr2);
        
        let stats = manager.get_stats();
        assert_eq!(stats.total_allocations, 2);
        assert_eq!(stats.current_allocated, 128);
        
        manager.dealloc(ptr1, layout).unwrap();
        manager.dealloc(ptr2, layout).unwrap();
    }

    #[test]
    fn test_allocator_suggestion() {
        let manager = AllocatorManager::new().unwrap();
        
        assert_eq!(
            manager.suggest_allocator(512, AllocationLifetime::Temporary),
            AllocatorType::Stack
        );
        
        assert_eq!(
            manager.suggest_allocator(2048, AllocationLifetime::Short),
            AllocatorType::Arena
        );
        
        assert_eq!(
            manager.suggest_allocator(4096, AllocationLifetime::Medium),
            AllocatorType::Slab
        );
        
        assert_eq!(
            manager.suggest_allocator(8192, AllocationLifetime::Long),
            AllocatorType::System
        );
    }
}