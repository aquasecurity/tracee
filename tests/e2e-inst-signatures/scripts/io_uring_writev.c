/*
 * this code is based on the very usefull and teaching repo: 
 * https://github.com/shuveb/loti-examples
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <linux/fs.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

/* If your compilation fails because the header file below is missing,
 * your kernel is probably too old to support io_uring.
 */
#include <linux/io_uring.h>

#define QUEUE_DEPTH 10
#define BLOCK_SZ    1024

/* This is x86 specific */
#define read_barrier()  __asm__ __volatile__("":::"memory")
#define write_barrier() __asm__ __volatile__("":::"memory")

struct app_io_sq_ring {
    unsigned *head;
    unsigned *tail;
    unsigned *ring_mask;
    unsigned *ring_entries;
    unsigned *flags;
    unsigned *array;
};

struct app_io_cq_ring {
    unsigned *head;
    unsigned *tail;
    unsigned *ring_mask;
    unsigned *ring_entries;
    struct io_uring_cqe *cqes;
};

struct submitter {
    int ring_fd;
    struct app_io_sq_ring sq_ring;
    struct io_uring_sqe *sqes;
    struct app_io_cq_ring cq_ring;
};

struct file_info {
    int fd;
    struct iovec iovecs[2];
};

/*
 * This code is written in the days when io_uring-related system calls are not
 * part of standard C libraries. So, we roll our own system call wrapper
 * functions.
 */
int io_uring_setup(unsigned entries, struct io_uring_params *p)
{
    return (int) syscall(__NR_io_uring_setup, entries, p);
}

int io_uring_enter(int ring_fd, unsigned int to_submit, unsigned int min_complete, unsigned int flags)
{
    return (int) syscall(__NR_io_uring_enter, ring_fd, to_submit, min_complete, flags, NULL);
}

/*
 * io_uring requires a lot of setup which looks pretty hairy, but isn't all
 * that difficult to understand. Because of all this boilerplate code,
 * io_uring's author has created liburing, which is relatively easy to use.
 * However, you should take your time and understand this code. It is always
 * good to know how it all works underneath. Apart from bragging rights,
 * it does offer you a certain strange geeky peace.
 */
int app_setup_uring(struct submitter *s) {
    void *sq_ptr, *cq_ptr;

    /*
     * We need to pass in the io_uring_params structure to the io_uring_setup()
     * call zeroed out. We could set any flags if we need to, but for this
     * example, we don't.
     */
    struct io_uring_params p = {0};
    s->ring_fd = io_uring_setup(QUEUE_DEPTH, &p);
    if (s->ring_fd < 0) {
        perror("io_uring_setup");
        return 1;
    }

    /*
     * io_uring communication happens via 2 shared kernel-user space ring buffers,
     * which can be jointly mapped with a single mmap() call in recent kernels. 
     * While the completion queue is directly manipulated, the submission queue 
     * has an indirection array in between. We map that in as well.
     */
    int sring_sz = p.sq_off.array + p.sq_entries * sizeof(unsigned);
    int cring_sz = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);

    /* In kernel version 5.4 and above, it is possible to map the submission and 
     * completion buffers with a single mmap() call. Rather than check for kernel 
     * versions, the recommended way is to just check the features field of the 
     * io_uring_params structure, which is a bit mask. If the 
     * IORING_FEAT_SINGLE_MMAP is set, then we can do away with the second mmap()
     * call to map the completion ring.
     */
    if (p.features & IORING_FEAT_SINGLE_MMAP) {
        if (cring_sz > sring_sz) {
            sring_sz = cring_sz;
        }
        cring_sz = sring_sz;
    }

    /* Map in the submission and completion queue ring buffers.
     * Older kernels only map in the submission queue, though.
     */
    sq_ptr = mmap(0, sring_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, s->ring_fd, IORING_OFF_SQ_RING);
    if (sq_ptr == MAP_FAILED) {
        perror("mmap sring");
        return 1;
    }

    if (p.features & IORING_FEAT_SINGLE_MMAP) {
        cq_ptr = sq_ptr;
    } else {
        /* Map in the completion queue ring buffer in older kernels separately */
        cq_ptr = mmap(0, cring_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, s->ring_fd, IORING_OFF_CQ_RING);
        if (cq_ptr == MAP_FAILED) {
            perror("mmap cring");
            return 1;
        }
    }

    /* Save useful fields in a global app_io_sq_ring struct for later easy reference */
    s->sq_ring.head = sq_ptr + p.sq_off.head;
    s->sq_ring.tail = sq_ptr + p.sq_off.tail;
    s->sq_ring.ring_mask = sq_ptr + p.sq_off.ring_mask;
    s->sq_ring.ring_entries = sq_ptr + p.sq_off.ring_entries;
    s->sq_ring.flags = sq_ptr + p.sq_off.flags;
    s->sq_ring.array = sq_ptr + p.sq_off.array;

    /* Map in the submission queue entries array */
    s->sqes = mmap(0, p.sq_entries * sizeof(struct io_uring_sqe), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, s->ring_fd, IORING_OFF_SQES);
    if (s->sqes == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    /* Save useful fields in a global app_io_cq_ring struct for later
     * easy reference 
     */
    s->cq_ring.head = cq_ptr + p.cq_off.head;
    s->cq_ring.tail = cq_ptr + p.cq_off.tail;
    s->cq_ring.ring_mask = cq_ptr + p.cq_off.ring_mask;
    s->cq_ring.ring_entries = cq_ptr + p.cq_off.ring_entries;
    s->cq_ring.cqes = cq_ptr + p.cq_off.cqes;

    return 0;
}

/*
 * Output a string of characters of len length to stdout.
 * We use buffered output here to be efficient,
 * since we need to output character-by-character.
 */
void output_to_console(char *buf, int len) {
    while (len--) {
        fputc(*buf++, stdout);
    }
}

/*
 * Read from completion queue.
 * In this function, we read completion events from the completion queue, get
 * the data buffer that will have the file data and print it to the console.
 */
int read_from_cq(struct submitter *s) {
    
    /*
     * Remember, this is a ring buffer. If head == tail, it means that the
     * buffer is empty.
     */
    read_barrier();
    unsigned head = *s->cq_ring.head;
    while (head != *s->cq_ring.tail) {
        /* Get the entry */
        int index = head & *s->cq_ring.ring_mask;
        struct io_uring_cqe *cqe = &s->cq_ring.cqes[index];
        if (cqe->res < 0) {
            fprintf(stderr, "Error: %s\n", strerror(abs(cqe->res)));
        }

        struct file_info *fi = (struct file_info*) cqe->user_data;

        printf("fd: %d\n", fi->fd);
        for (int i = 0; i < 2; i++){
            output_to_console(fi->iovecs[i].iov_base, fi->iovecs[i].iov_len);
        }
        printf("finish fd: %d\n", fi->fd);

        head++;
    }

    *s->cq_ring.head = head;
    write_barrier();

    return 0;
}

int prepare_file_info(char *file_path, struct file_info **fi, char *buf1, char *buf2){
    int file_fd = open(file_path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (file_fd < 0 ) {
        perror("open");
        return 1;
    }

    *fi = malloc(sizeof(struct file_info));
    if (fi == NULL) {
        fprintf(stderr, "Unable to allocate memory\n");
        return 1;
    }
    (*fi)->fd = file_fd;
    
    (*fi)->iovecs[0].iov_base = (void*)buf1;
    (*fi)->iovecs[0].iov_len = strlen(buf1);

    fprintf(stdout, "first iov buffer len: %d\n", (*fi)->iovecs[0].iov_len);

    (*fi)->iovecs[1].iov_base = (void*)buf2;
    (*fi)->iovecs[1].iov_len = strlen(buf2);

    fprintf(stdout, "second iov buffer len: %d\n", (*fi)->iovecs[1].iov_len);

    return 0;
}

int add_entry_to_sq(struct submitter *s, struct file_info *fi){
    unsigned tail = 0, next_tail = 0;

    /* Add our submission queue entry to the tail of the SQE ring buffer */
    next_tail = tail = *s->sq_ring.tail;
    next_tail++;
    int index = tail & *s->sq_ring.ring_mask;
    read_barrier();
    
    struct io_uring_sqe *sqe = &s->sqes[index];

    sqe->fd = fi->fd;
    sqe->flags = 0;
    sqe->opcode = IORING_OP_WRITEV;
    sqe->addr = (unsigned long) fi->iovecs;
    sqe->len = 2;
    sqe->off = 0;
    sqe->user_data = (unsigned long long) fi;
    s->sq_ring.array[index] = index;
    tail = next_tail;

    /* Update the tail so the kernel can see it. */
    if(*s->sq_ring.tail != tail) {
        *s->sq_ring.tail = tail;
        write_barrier();
    }

    return 0;
}

/*
 * Submit to submission queue.
 * In this function, we submit requests to the submission queue. You can submit
 * many types of requests. Ours is going to be the readv() request, which we
 * specify via IORING_OP_READV.
 */
int submit_file_to_sq(char *file_path, struct submitter *s, char *buf1, char *buf2) {
    struct file_info *fi;
    int ret = prepare_file_info(file_path, &fi, buf1, buf2);
    if (ret != 0) {
        return ret;
    }

    ret = add_entry_to_sq(s, fi);
    if (ret != 0) {
        return ret;
    }

    return 0;
}

int main(int argc, char *argv[]) {

    char buf1[] = "first line.\n";
    char buf2[] = "second and last line.\n";

    struct submitter s = {0};
    if(app_setup_uring(&s)) {
        fprintf(stderr, "Unable to setup uring!\n");
        return 1;
    }

    printf("setup uring success\n");

    if(submit_file_to_sq("/tmp/io_uring_writev.txt", &s, buf1, buf2)) {
        fprintf(stderr, "Error reading file\n");
        return 1;
    }

    /*
     * Tell the kernel we have submitted events with the io_uring_enter() system
     * call. We also pass in the IOURING_ENTER_GETEVENTS flag which causes the
     * io_uring_enter() call to wait until min_complete events (the 3rd param)
     * complete.
     */
    int ret = io_uring_enter(s.ring_fd, 1, 1, IORING_ENTER_GETEVENTS);
    if(ret < 0) {
        perror("io_uring_enter");
        return 1;
    }

    printf("io_uring_enter success\n");

    ret = read_from_cq(&s);
    if (ret != 0){
        perror("read_from_cq");
        return 1;
    }

    printf("read_from_cq success\n");

    return 0;
}