static int pagemap_fd;

uint64_t phys_page(uint64_t virt_page)
{
  if (pagemap_fd == 0) {
    if ((pagemap_fd = fopen("/proc/%d/pagemap", O_RD)) <= 0) {
      perror("open pagemap");
      return 0;
    }
  }
  uint64_t data;
  int len;
  len = pread(pagemap_fd, &data, sizeof(data), virt_page * sizeof(uint64_t));
  if (len != sizeof(data)) {
    perror("pread");
    return 0;
  }
  if (data & (1<<63) == 0) {
    fprintf(stderr, "page %x not present: %x", virt_page, data);
    return 0;
  }
  return data & ((1 << 55) - 1);
}

