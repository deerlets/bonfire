package bonfire

// #cgo CFLAGS:
// #cgo LDFLAGS: -lbonfire
// #include <bonfire.h>
//extern void __cgo_bonfire_service_cb(struct bmsg *bm);
import "C"
import "unsafe"
import "time"

const (
    FLAG_STOPPED int = 0
    FLAG_RUNNING = 1
    FLAG_STOPPING = 2
)

type Bonfire struct {
    __bf *C.struct_bonfire
    service_map map[string]func (*Bmsg)
    flag int
}

type Bmsg struct {
    __bmsg *C.struct_bmsg
}

var bmap map[*C.struct_bonfire]*Bonfire = make(map[*C.struct_bonfire]*Bonfire)

func (bm *Bmsg) WriteResponse(data string) {
    C.bmsg_write_response(bm.__bmsg, C.CString(data))
}

func (bf *Bonfire) New() {
    bf.__bf = C.bonfire_new()
    bf.service_map = make(map[string]func (*Bmsg))
    bf.flag = FLAG_STOPPED
    bmap[bf.__bf] = bf
}

func (bf *Bonfire) Destroy() {
    if bf.flag == FLAG_RUNNING {
        bf.flag = FLAG_STOPPING
    }
    for bf.flag != FLAG_STOPPED {
        time.Sleep(1 * time.Second)
    }
    delete(bmap, bf.__bf)
    C.bonfire_destroy(bf.__bf)
}

func (bf *Bonfire) Connect(address string) {
    C.bonfire_connect(bf.__bf, C.CString(address))
}

func (bf *Bonfire) Disconnect() {
    C.bonfire_disconnect(bf.__bf)
}

func (bf *Bonfire) Loop(timeout uint32) {
    bf.flag = FLAG_RUNNING
    for bf.flag == FLAG_RUNNING {
        C.bonfire_loop(bf.__bf, C.long(timeout));
    }
    bf.flag = FLAG_STOPPED
}

//export __cgo_bonfire_service_cb
func __cgo_bonfire_service_cb(bm *C.struct_bmsg) {
    var bf *Bonfire = bmap[C.bmsg_get_bonfire(bm)]
    var header *C.char
    var size C.size_t
    C.bmsg_get_request_header(bm,
        (*unsafe.Pointer)(unsafe.Pointer(&header)), &size)
    var bmsg Bmsg
    bmsg.__bmsg = bm
    bf.service_map[C.GoString(header)](&bmsg)
}

func (bf *Bonfire) AddService(header string, cb func (*Bmsg)) {
    bf.service_map[header] = cb
    C.bonfire_add_service(bf.__bf, C.CString(header),
        C.bonfire_service_cb(C.__cgo_bonfire_service_cb))
}

func (bf *Bonfire) DelService(header string) {
    C.bonfire_del_service(bf.__bf, C.CString(header))
    delete(bf.service_map, header)
}

func (bf *Bonfire) Servcall(header string, content string) (string) {
    var result *C.char
    C.bonfire_servcall(bf.__bf, C.CString(header), C.CString(content), &result)
    return C.GoString(result)
}

// bonfire borker

type BonfireBroker struct {
    __brk *C.struct_bonfire_broker
    flag int
}

func (brk *BonfireBroker) New(address string) {
    brk.__brk = C.bonfire_broker_new(C.CString(address))
    brk.flag = FLAG_STOPPED
}

func (brk *BonfireBroker) Destroy() {
    if brk.flag == FLAG_RUNNING {
        brk.flag = FLAG_STOPPING
    }
    for brk.flag != FLAG_STOPPED {
        time.Sleep(1 * time.Second)
    }
    C.bonfire_broker_destroy(brk.__brk)
}

func (brk *BonfireBroker) Loop(timeout uint32) {
    brk.flag = FLAG_RUNNING
    for brk.flag == FLAG_RUNNING {
        C.bonfire_broker_loop(brk.__brk, C.long(timeout))
    }
    brk.flag = FLAG_STOPPED
}
