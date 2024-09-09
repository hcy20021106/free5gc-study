# Race Condition
two or more goroutines access a shared resource concurrently, and at least one of the goroutines modifies the resource.
for example:
```bash
package main

import (
    "fmt"
    "sync"
)

func main() {
    var counter int
    var wg sync.WaitGroup

    for i := 0; i < 1000; i++ {
        wg.Add(1)
        go func() {
            counter++
            wg.Done()
        }()
    }

    wg.Wait()
    fmt.Println(counter)
}
```

# Mutex
It is a synchronization mechansim for protecting shared resources from concurrent access. A mutex is used to unsure that only one goroutine can access the shared resource at a time.
```bash
package main

import (
    "fmt"
    "sync"
)

func main() {
    var counter int
    var mu sync.Mutex

    mu.Lock()
    counter++
    mu.Unlock()

    fmt.Println(counter)
}package main

import (
    "fmt"
    "sync"
)

func main() {
    var counter int
    var mu sync.Mutex

    mu.Lock()
    counter++
    mu.Unlock()

    fmt.Println(counter)
}
```


# Atomic Operations
```bash
package main

import (
    "fmt"
    "sync/atomic"
)

func main() {
    var counter int32
    atomic.AddInt32(&counter, 1)
    fmt.Println(counter)
}
```

# Channel
Goroutines run in the same address space, so access to shared memory must be synchronized. Channel is used to provide an effective communication mechanism that allows gorountines to safely exchange information without requiring additional synchronization mechanisms.
To create a channel, use **make** function to establish an integer-type channel.

# Unbuffered channel
We do not assign channel a capacity value, by default with 0 instead. It can guarantee that both read and write operations must be completed before the main program finished, achieving **synchronization**.
```bash
func main() {
    c := make(chan bool)
    go func() {
        fmt.Println("free5GC so Good")
        c <- true
    }()
    <-c
}
```

# Buffered channel
It is different from unbuffered channels as long as the it has sufficient capacity. It can continue receiving values without requiring them to be read immediately. 

# Unidirectional Channel
It only allows send or receive operations, which provides higher security and readability in programs. 
```bash
func Thread(r <-chan int) {
    for {
        num := <-r
        fmt.Println("Thread : ", num)
        time.Sleep(time.Second)
    }
}

func main() {
    c := make(chan int, 3)
    s, r := (chan<- int)(c), (<-chan int)(c)
    go Thread(r)
    for i := 1; i <= 10; i++ {
        s <- i
    }
    for len(c) > 0 {
        time.Sleep(100)
    }
}
```


# Select
It is for the context in which there are multiple channels or communication. It allows goroutine to wait on multiple communication operations simultaneously. 
- **select** can only work with channels, using other types will result to error.
- When none of the cases are ready, **select** executes the **default**
```bash
func main() {
    ch := make(chan int, 1)

    select {
    case <-ch:
        fmt.Println("random 01")
    case <-ch:
        fmt.Println("random 02")
    default:
        fmt.Println("exit")
    }
}

```
# WaitGroup
It is used to control the concurrency. For example, you need to make the main goroutine wait for the other goroutines being completed before continuing execution.
```bash
wg := &sync.WaitGroup{}
or
wg := new(sync.WaitGroup)
or
var wg = &sync.WaitGroup{} //global declaration


func main() {
var wg sync.WaitGroup

    wg.Add(2)//integer means the amounts you have to wait
gofunc() {
        time.Sleep(2 * time.Second)
        fmt.Println("job 1 done.")
        wg.Done()
    }()
gofunc() {
        time.Sleep(1 * time.Second)
        fmt.Println("job 2 done.")
        wg.Done()
    }()
    wg.Wait() // make the main goroutine waiting other goroutines
    fmt.Println("All Done.")
}
```
## Notice
**wg.done()** must correspond to every **wd.Add()**
- goroutines numbers > wg.Add numbers : some goroutines would not execute
- goroutines numbers < wg.Add numbers : cause Deadlock


# Context
Context is another method to control concurrency, It can manage the termination of multiple goroutines and resources allocation. It can be used to **proactively** notify and stop running jobs. 
```bash
func main() {
    ctx, cancel := context.WithCancel(context.Background())

    go worker(ctx, "node01")
    go worker(ctx, "node02")
    go worker(ctx, "node03")

    time.Sleep(5 * time.Second) //stop the context (goroutine) after 5 seconds
    fmt.Println("stop the gorutine")
    cancel()
    time.Sleep(5 * time.Second) //canceling needs some time
}

func worker(ctx context.Context, name string) {
    for {
        select {
        case <-ctx.Done(): //ctx is canceled, from withCancel function
            fmt.Println(name, "got the stop channel")
            return
        default:
            fmt.Println(name, "still working")
            time.Sleep(1 * time.Second)
        }
    }
}
```
