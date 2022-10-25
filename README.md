## IDAPython >= 7.4 

### Clear output window 

```python
    form = ida_kernwin.find_widget("Output window")
    ida_kernwin.activate_widget(form, True)
    idaapi.process_ui_action("msglist:Clear")
```

### Compute function length
```python
def compute_function_length(ea):
    return idc.get_func_attr(ea, idc.FUNCATTR_END) - ea
```

### C++ Name demangling
```python
func_name = idc.get_func_name(f)
demangled_name = idc.demangle_name(func_name, idc.get_inf_attr(idc.INF_SHORT_DN))
```     

### Jump to from QModelIndex

```python
# where 1 is the column with the address
idaapi.jumpto(int(item.sibling(item.row(), 1).data(), 16))
```

### Get all subcalls from a function
```python
def get_function_called(ea):
    funcs = []
    for h in idautils.FuncItems(ea):
        for r in idautils.XrefsFrom(h, 0):
            if r.type == idautils.ida_xref.fl_CF or r.type == idautils.ida_xref.fl_CN:
                funcs.append(r.to)
    return funcs
```

### Search for pattern across whole binary
```python
sequence = "83 F8 01"
found_ea = ida_ida.inf_get_min_ea()-1
end_ea = ida_ida.inf_get_max_ea()
print(f"Looking for pattern in {hex(found_ea+1)}-{hex(end_ea)}")
while True:
    found_ea = idaapi.find_binary(found_ea+1, end_ea, needle, 16, idaapi.SEARCH_DOWN)
    if found_ea == idaapi.BADADDR: break
    print(f"Found at {hex(found_ea)}")
```

### Verify if address is mapped/valid
```python
addr = 0xdeadbeef
if addr >= ida_ida.inf_get_min_ea() and addr <= ida_ida.inf_get_max_ea():
    print("Valid address!")
```

### Start

```python
from ida_dbg import start_process
start_process()
```

## Debugging

### Attach to a process

```python
target = "Process.exe"
pis = ida_idd.procinfo_vec_t()
count = ida_dbg.get_processes(pis)
print(f"Found {count}")
for p in pis:
    print(f"{p.pid}: {p.name}")
    if target in p.name:
        print(f"Attaching to process {p.name}")
        ida_dbg.attach_process(p.pid)
```

### Add breakpoint
```python
from ida_dbg import add_bpt
add_bpt(address)
```

### Refresh memory of debugger
```python
from ida_dbg import refresh_debugger_memory
refresh_debugger_memory()
```
### Read memory
```python
from ida_bytes import *
get_byte(ea, size)
get_dword(ea)
get_qword(ea)
```

### Read register
```python
from ida_dbg import get_reg_val
rcx = get_reg_val("rcx")
```

## PyQt5 related

### Add QIcon without including a file (base64 encoded)
```python
toolbar = QtWidgets.QToolBar()
saveImg = QtGui.QPixmap()
saveImg.loadFromData(base64.b64decode("BASE64ENCODEDICON))
saveAction = QtWidgets.QAction(QtGui.QIcon(saveImg), "Save", parent)
toolbar.addAction(saveAction)
```
