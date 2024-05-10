use io_uring::{opcode, types, IoUring};
use std::env;
use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::time::Instant;

// Define the time_it macro
macro_rules! time_it {
    ($message:expr, $block:block) => {{
        let start = Instant::now();
        let result = $block;
        println!("{}: {:?}", $message, start.elapsed());
        result
    }};
}

fn libc_version() {
    unsafe {
        let msg = "Hello, syscall!\n";
        let len = msg.len();
        // 转换字符串为 C 风格的字符串（以 null 结尾）
        let c_msg = std::ffi::CString::new(msg).expect("CString::new failed");
        // 调用 write 系统调用写入到标凈输出
        let written = libc::syscall(libc::SYS_write, 1, c_msg.as_ptr(), len);
    }
}

fn main() {
    libc_version();
    let mut ring = time_it!("Setup IoUring", { IoUring::new(8).unwrap() });
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <filename>", args[0]);
        std::process::exit(1);
    }

    let filename = &args[1];

    // Open file and measure time using macro
    let fd = time_it!("Open file", { File::open(filename).unwrap() });

    let mut buf = vec![0; 1024];
    let read_op = opcode::Read::new(types::Fd(fd.as_raw_fd()), buf.as_mut_ptr(), buf.len() as _)
        .build()
        .user_data(0x42);

    // Submit the read operation and measure time using macro
    time_it!("Submit", {
        unsafe {
            ring.submission()
                .push(&read_op)
                .expect("Submission queue is full");
        }
    });
    let result = time_it!("submit", { ring.submit().unwrap() });
    assert_eq!(result, 1);
    // std::thread::sleep(std::time::Duration::from_millis(150));
    // Wait for the operation to complete and measure time using macro
    time_it!("Wait", {
        ring.submit_and_wait(1).unwrap();
    });

    // Handle completion and measure time using macro
    let cqe = time_it!("Completion", {
        ring.completion().next().expect("completion queue is empty")
    });

    assert_eq!(cqe.user_data(), 0x42);
    assert!(cqe.result() >= 0);

    let s = std::str::from_utf8(&buf[..cqe.result() as usize]).unwrap();
    println!("{}", s);
}
