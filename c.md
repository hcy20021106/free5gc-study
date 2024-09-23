# & operation
```bash
far->action = 0b10101010;  // 假设这是二进制表示的 action
FAR_ACTION_MASK = 0b00001111;  // 掩码只取低4位

result = far->action & FAR_ACTION_MASK;
// result = 0b00001010  (只取低4位的值)
```
# #define宏
#define is used to skip header of struct to access the actual data.
```bash
struct nlattr{
    _u16 nla_len;
    _u16 nla_type
    //后面紧跟数据部分
}
struct nlattr *na
int *value;
value = (int *)NLA_DATA(na);
```

# strcpy
char * strcpy(char *destination, const char *source)

# strncpy
char *strncpy(char *destination, const char *source, size_t num)
> const char可以保证不被修改

# memcpy
void* memcpy(void* dest, const void* src, std::size_t count)
```bash
char source[] = "once upon a daydream...", dest[4];
std::memcpy(dest, source, sizeof dest);
```

# malloc
void *memset(void *ptr, int value, size_t num)
```bash
size_t num_elements = 10;
int *buffer = malloc(num_elements * sizeof(int));

```
# calloc
void *calloc(size_t num, size_t size);
```bash
int* arr = (int*) calloc(10, sizeof(int)); // 分配并初始化为 0 的 10 个整数的内存

```

# void*
void* is a pointer to point a uncertain type. 不能直接对void*指针进行解引用操作，必须先将其转换为具体类型的指针
```bash
void* ptr;
int num = 10;
ptr = &num;
int* intPtr = (int*)ptr;

```

# struct *
```bash
void  *server_addr;
server_addr = malloc(sizeof(struct sockaddr_in));
struct sockaddr_in *addr = (struct sockaddr_in *) server_addr;

```
# int main(int argc, char *argv[])
```bash
int main(int argc, char *argv[]){
    if(argc !=3 ){
        fprintf(stderr, "")
        return 1;
    }
}
```
```bash
gcc -o set_mtu set_mtu.c
sudo ./set_mtu eth0 1500
```
# read
ssize_t read(int fd, void buf[.count], size_t count);

# fd
socket(), open()的返回值都是fd，本质是int，用于描述文件

# 对齐（强制转换的基础）
- 内存对齐：通常指大小一样。
```bash
char buffer[sizeof(struct iphdr)];
```
- 数据布局对齐
例如填充buffer时需要确保字段按正常的顺序和格式进行填充

# __init && __exit
__init和__exit是宏，标记函数分别在模块初始化和模块卸载时被调用