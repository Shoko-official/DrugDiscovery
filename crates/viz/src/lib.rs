#![deny(unsafe_code)]

#[derive(Debug, Clone, Copy)]
pub struct FrameBudget {
    pub target_fps: u32,
    pub max_gpu_memory_mb: u32,
}

pub trait ScientificRenderer {
    fn set_frame_budget(&mut self, budget: FrameBudget);
    fn lose_device_for_test(&mut self);
    fn recover_device(&mut self) -> Result<(), RenderError>;
}

#[derive(Debug)]
pub enum RenderError {
    DeviceUnavailable,
    OutOfMemory,
}
