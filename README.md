# IDAPython >= 7.4 

#### Clear output window 

```python
    form = ida_kernwin.find_widget("Output window")
    ida_kernwin.activate_widget(form, True);
    idaapi.process_ui_action("msglist:Clear")
```

#### Compute function length
```python
def compute_function_length(ea):
    return idc.get_func_attr(ea, idc.FUNCATTR_END) - ea
```

#### C++ Name demangling
```python
func_name = idc.get_func_name(f)
demangled_name = idc.demangle_name(func_name, idc.get_inf_attr(idc.INF_SHORT_DN))
```     

#### Jump to from QModelIndex

```python
# where 1 is the column with the address
idaapi.jumpto(int(item.sibling(item.row(), 1).data(), 16))
```

#### Get all subcalls from a function
```python
def get_function_called(ea):
    funcs = []
    for h in idautils.FuncItems(ea):
        for r in idautils.XrefsFrom(h, 0):
            if r.type == idautils.ida_xref.fl_CF or r.type == idautils.ida_xref.fl_CN:
                funcs.append(r.to)
    return funcs
```
