package bonfire

import "fmt"
import "testing"

func TestBase(T *testing.T) {
    // Init broker
    var brk BonfireBroker
    brk.New("tcp://127.0.0.1:51338")
    go brk.Loop(1000)

    // Init bonfire cli
    var bf Bonfire
    bf.New()
    bf.Connect("tcp://127.0.0.1:51338")
    bf.AddService("golang://hello", func (bmsg *Bmsg) {
        bmsg.WriteResponse("hello golang for bonfire")
    })
    go bf.Loop(1000)

    rs := bf.Servcall("golang://hello", "{}")
    fmt.Println(rs)

    bf.DelService("golang://hello")
    bf.Disconnect()
    bf.Destroy()
    brk.Destroy()
}
