use libc::{c_int, syscall, SYS_io_uring_enter, SYS_io_uring_setup};

use bitflags::bitflags;

bitflags! {
    #[derive(Default,Debug)]
    pub struct IoUringFeatures: u32 {
        const SINGLE_MMAP = 1 << 0;
        const NODROP = 1 << 1;
        const SUBMIT_STABLE = 1 << 2;
        const RW_CUR_POS = 1 << 3;
        const CUR_PERSONALITY = 1 << 4;
        const FAST_POLL = 1 << 5;
        const POLL_32BITS = 1 << 6;
        const SQPOLL_NONFIXED = 1 << 7;
        const EXT_ARG = 1 << 8;
        const NATIVE_WORKERS = 1 << 9;
        const RSRC_TAGS = 1 << 10;
        const CQE_SKIP = 1 << 11;
        const LINKED_FILE = 1 << 12;
        const REG_REG_RING = 1 << 13;
    }
}

#[repr(C)]
#[derive(Default, Debug)]
struct io_sqring_offsets {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    flags: u32,
    dropped: u32,
    array: u32,
    resv1: u32,
    user_addr: u64,
}

#[repr(C)]
#[derive(Default, Debug)]
struct io_cqring_offsets {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    overflow: u32,
    cqes: u32,
    flags: u32,
    resv1: u32,
    user_addr: u64,
}

#[repr(C)]
#[derive(Default, Debug)]
struct io_uring_params {
    sq_entries: u32,
    cq_entries: u32,
    flags: u32,
    sq_thread_cpu: u32,
    sq_thread_idel: u32,
    features: IoUringFeatures,
    wq_fd: u32,
    resv: [u32; 3],
    sq_off: io_sqring_offsets,
    cq_off: io_cqring_offsets,
}

/// Setup io_uring instance.
///
/// # Returns
/// Returns the file descriptor of the io_uring instance on success, or a negative error number on failure.
fn io_uring_setup(entries: u32, p: *mut io_uring_params) -> i64 {
    unsafe { syscall(SYS_io_uring_setup, entries, p) }
}

#[repr(C)]
#[derive(Debug)]
struct AppSQRing {
    head: *mut u32,
    tail: *mut u32,
    ring_mask: *mut u32,
    ring_entries: *mut u32,
    flags: *mut u32,
    array: *mut u32,
}

impl Default for AppSQRing {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

#[repr(C)]
struct IoUringCQE {
    user_data: u64,
    res: i32,
    flags: u32,
    big_cqe: [u64; 0],
}

#[repr(C)]
pub struct IoUringSqe {
    opcode: u8,
    flags: u8,
    ioprio: u16,
    fd: i32,
    off_addr2: OffAddr2,
    addr_splice_off_in: AddrSpliceOffIn,
    len: u32,
    rw_flags_fsync_flags: RwFlagsFsyncFlags,
    user_data: u64,
    buf_index_buf_group: BufIndexBufGroup,
    personality: u16,
    splice_fd_in_file_index_optlen: SpliceFdInFileIndexOptlen,
    addr3_optval_cmd: Addr3OptvalCmd,
}

impl Default for IoUringSqe {
    fn default() -> Self {
        // Create from a zeroed memory
        unsafe { std::mem::zeroed() }
    }
}

#[repr(C)]
union OffAddr2 {
    off: u64,
    addr2: u64,
    cmd_op_pad: CmdOpPad,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CmdOpPad {
    cmd_op: u32,
    __pad1: u32,
}

#[repr(C)]
union AddrSpliceOffIn {
    addr: u64,
    splice_off_in: u64,
    level_optname: LevelOptname,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct LevelOptname {
    level: u32,
    optname: u32,
}

#[repr(C)]
union RwFlagsFsyncFlags {
    rw_flags: u32, // You will need to define __kernel_rwf_t based on your usage.
    fsync_flags: u32,
    poll_events: u16,
    poll32_events: u32,
    sync_range_flags: u32,
    msg_flags: u32,
    timeout_flags: u32,
    accept_flags: u32,
    cancel_flags: u32,
    open_flags: u32,
    statx_flags: u32,
    fadvise_advice: u32,
    splice_flags: u32,
    rename_flags: u32,
    unlink_flags: u32,
    hardlink_flags: u32,
    xattr_flags: u32,
    msg_ring_flags: u32,
    uring_cmd_flags: u32,
    waitid_flags: u32,
    futex_flags: u32,
    install_fd_flags: u32,
}

#[repr(C)]
#[repr(packed)]
struct BufIndexBufGroup {
    buf_index: u16,
    buf_group: u16,
}

#[repr(C)]
union SpliceFdInFileIndexOptlen {
    splice_fd_in: i32,
    file_index: u32,
    optlen: u32,
    addr_len_pad: AddrLenPad,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct AddrLenPad {
    addr_len: u16,
    __pad3: [u16; 1],
}

#[repr(C)]
union Addr3OptvalCmd {
    addr3: u64,
}

#[repr(C)]
#[derive(Debug)]
struct AppCQRing {
    head: *mut u32,
    tail: *mut u32,
    ring_mask: *mut u32,
    ring_entries: *mut u32,
    cqes: *mut IoUringCQE,
}

impl Default for AppCQRing {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

#[repr(C)]
struct Submitter {
    ring_fd: c_int,
    sq_ring: AppSQRing,
    cq_ring: AppCQRing,
    sqes: *mut IoUringSqe,
}

impl Default for Submitter {
    fn default() -> Self {
        Submitter {
            ring_fd: 0,
            sq_ring: AppSQRing::default(),
            cq_ring: AppCQRing::default(),
            sqes: std::ptr::null_mut(),
        }
    }
}

#[repr(C)]
struct IoVec {
    base: *mut u8,
    len: usize,
}

fn main() {
    assert_eq!(std::mem::size_of::<IoUringCQE>(), 16);
    assert_eq!(std::mem::size_of::<OffAddr2>(), 8);
    assert_eq!(std::mem::size_of::<AddrSpliceOffIn>(), 8);
    assert_eq!(std::mem::size_of::<BufIndexBufGroup>(), 4);
    assert_eq!(std::mem::size_of::<SpliceFdInFileIndexOptlen>(), 4);
    assert_eq!(std::mem::size_of::<Addr3OptvalCmd>(), 8);
    assert_eq!(std::mem::size_of::<IoUringSqe>(), 64);
    let mut p = io_uring_params::default();
    assert_eq!(std::mem::size_of::<io_uring_params>(), 120);
    let ring_fd = io_uring_setup(1, &mut p);
    if ring_fd < 0 {
        eprintln!("io_uring_setup failed: {}", ring_fd);
    }

    println!("After io_uring_setup: {:#?}", p);
    // Check io_uring features support IORING_FEAT_SINGLE_MMAP
    if !p.features.contains(IoUringFeatures::SINGLE_MMAP) {
        eprintln!("IORING_FEAT_SINGLE_MMAP not supported(kernel version >= 5.4 required)");
    }
    // TODO: not use the size_of a u32, but the size of the type
    assert_eq!(p.sq_off.array, 128);
    assert_eq!(p.sq_entries, 1);
    let submit_ring_size = p.sq_off.array + p.sq_entries * std::mem::size_of::<c_int>() as u32;
    assert_eq!(submit_ring_size, 132);
    let completion_ring_size =
        p.cq_off.cqes + p.cq_entries * std::mem::size_of::<IoUringCQE>() as u32;
    assert_eq!(completion_ring_size, 96);
    let ring_size = if submit_ring_size > completion_ring_size {
        submit_ring_size
    } else {
        completion_ring_size
    };
    assert_eq!(ring_size, 132);
    // Map in the submission and completion queue ring buffers.
    let sq_ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            ring_size as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_POPULATE,
            ring_fd as c_int,
            // IORING_OFF_SQ_RING == 0ULL
            // IORING_OFF_CQ_RING == 0x8000000ULL
            0,
        )
    };

    if sq_ptr == libc::MAP_FAILED {
        eprintln!("mmap failed: {}", std::io::Error::last_os_error());
    }
    let cq_ptr = sq_ptr;
    println!("Mmap success: sq_ptr: {:p}, cq_ptr: {:p}", sq_ptr, cq_ptr);

    let mut submitter = Submitter::default();
    let sring = &mut submitter.sq_ring;

    assert_eq!(p.sq_off.head, 0);
    sring.head = unsafe { sq_ptr.add(p.sq_off.head as usize) as *mut u32 };
    assert_eq!(p.sq_off.tail, 4);
    sring.tail = unsafe { sq_ptr.add(p.sq_off.tail as usize) as *mut u32 };
    assert_eq!(p.sq_off.ring_mask, 16);
    sring.ring_mask = unsafe { sq_ptr.add(p.sq_off.ring_mask as usize) as *mut u32 };
    assert_eq!(p.sq_off.ring_entries, 24);
    sring.ring_entries = unsafe { sq_ptr.add(p.sq_off.ring_entries as usize) as *mut u32 };
    assert_eq!(p.sq_off.flags, 36);
    sring.flags = unsafe { sq_ptr.add(p.sq_off.flags as usize) as *mut u32 };
    assert_eq!(p.sq_off.array, 128);
    sring.array = unsafe { sq_ptr.add(p.sq_off.array as usize) as *mut u32 };
    println!("After setting sring: {:#?}", sring);

    // Map in the submission and completion queue ring buffers.
    submitter.sqes = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            p.sq_entries as usize * std::mem::size_of::<IoUringSqe>(),
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_POPULATE,
            ring_fd as c_int,
            // IORING_OFF_SQES == 0x10000000ULL
            0x10000000,
        ) as *mut IoUringSqe
    };
    if submitter.sqes == libc::MAP_FAILED as *mut IoUringSqe {
        eprintln!("mmap failed: {}", std::io::Error::last_os_error());
    }

    let cring = &mut submitter.cq_ring;
    cring.head = unsafe { cq_ptr.add(p.cq_off.head as usize) as *mut u32 };
    cring.tail = unsafe { cq_ptr.add(p.cq_off.tail as usize) as *mut u32 };
    cring.ring_mask = unsafe { cq_ptr.add(p.cq_off.ring_mask as usize) as *mut u32 };
    cring.ring_entries = unsafe { cq_ptr.add(p.cq_off.ring_entries as usize) as *mut u32 };
    cring.cqes = unsafe { cq_ptr.add(p.cq_off.cqes as usize) as *mut IoUringCQE };
    println!("After setting cring: {:#?}", cring);

    let file_fd = unsafe { libc::open("Cargo.toml\0".as_ptr() as *const i8, libc::O_RDONLY) };
    if file_fd < 0 {
        eprintln!("open failed: {}", std::io::Error::last_os_error());
    }

    let mut tail = unsafe { *sring.tail };
    assert_eq!(tail, 0);
    let ring_mask = unsafe { *sring.ring_mask };
    assert_eq!(ring_mask, 0);
    let index = tail & ring_mask;
    assert_eq!(index, 0);

    let sqe = unsafe { &mut *submitter.sqes.offset(index as isize) };
    // Create a 4kb buffer
    let buffer = vec![0u8; 4096];
    let iovec = IoVec {
        base: buffer.as_ptr() as *mut u8,
        len: buffer.len(),
    };

    sqe.fd = file_fd;
    sqe.flags = 0;
    sqe.opcode = 1;
    sqe.addr_splice_off_in.addr = &iovec as *const IoVec as u64;
    sqe.len = 1;
    sqe.off_addr2.off = 0;
    sqe.user_data = 0x1234;

    // Update the tail after writing the SQE
    unsafe { *sring.tail = tail + 1 };

    let ret = unsafe { syscall(SYS_io_uring_enter, ring_fd, 1, 1, 0, 0, 0) };
    assert_eq!(ret, 1);

    let head = cring.head;

    let cqe = unsafe { &*cring.cqes.offset(*head as isize) };
    if cqe.res < 0 {
        eprintln!("cqe.res < 0: {}", cqe.res);
    }
    // Print the buffer
    let content: String = buffer.iter().map(|&c| c as char).collect();
    println!("Content: {}", content);
}
