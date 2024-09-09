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

# memcpy
void* memcpy(void* dest, const void* src, std::size_t count)
```bash
char source[] = "once upon a daydream...", dest[4];
std::memcpy(dest, source, sizeof dest);
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
