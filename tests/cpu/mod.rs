//! The CPU time this whole process has used, for the tests that measure a channel at rest.

use std::time::Duration;

#[cfg(windows)]
pub fn process_cpu() -> Duration {
    #[repr(C)]
    #[derive(Default, Clone, Copy)]
    struct FileTime {
        low: u32,
        high: u32,
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> isize;
        fn GetProcessTimes(
            process: isize,
            created: *mut FileTime,
            exited: *mut FileTime,
            kernel: *mut FileTime,
            user: *mut FileTime,
        ) -> i32;
    }
    let mut times = [FileTime::default(); 4];
    let [created, exited, kernel, user] = &mut times;
    // SAFETY: each pointer is a live out-parameter of the size the call writes.
    let done = unsafe { GetProcessTimes(GetCurrentProcess(), created, exited, kernel, user) };
    assert_ne!(done, 0);
    let ticks = |time: &FileTime| (u64::from(time.high) << 32) | u64::from(time.low);
    Duration::from_nanos((ticks(kernel) + ticks(user)) * 100)
}

#[cfg(target_os = "linux")]
pub fn process_cpu() -> Duration {
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap();
    let after_name = stat.rsplit(')').next().unwrap();
    let fields: Vec<&str> = after_name.split_whitespace().collect();
    // utime and stime, counted from the state field, in clock ticks of 10 ms on every kernel this runs on.
    let ticks: u64 = fields[11].parse::<u64>().unwrap() + fields[12].parse::<u64>().unwrap();
    Duration::from_millis(ticks * 10)
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn process_cpu() -> Duration {
    Duration::ZERO
}
