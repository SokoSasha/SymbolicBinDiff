import angr
from pprint import *
from idautils import *
from idaapi import *
from idc import *

print("Init...")
# Angr project of a current programm
#                       file in IDA          no libs needed                              file base address
proj = angr.Project(get_input_file_path(), auto_load_libs=False, main_opts={'base_addr' : get_imagebase()})
print("Done")

# A list of main functions and their addresses (IDA)
print("Collecting functions...")
main_funcs = []
for ea in Functions():
    if not get_func_flags(ea) & (FUNC_LIB | FUNC_THUNK | FUNC_FAR | FUNC_NORET):
        main_funcs.append([ea, ida_funcs.get_func_name(ea)])
print("Done!")

#entry point (IDA)
info = get_inf_structure()
func_addr = info.start_ip

# just some output for me
# print("=== Block ===")
# print(entrypoint)
# block = proj.factory.block(entrypoint)
# print(block.pp())
# print("=== Block end ===")

# print("idapy funcs:", len(main_funcs))
# for func in main_funcs:
#    print(func[1], "at", hex(func[0]))


# Starting angr proj
print("Making state...")
state = proj.factory.entry_state()
path = proj.factory.path(state=state)
path = path.step(num_inst=1).successors[0]
path_addr = path.addr

while path_addr != func_addr:
    path = path.step(num_inst=1).successors[0]
    path_addr = path.addr

# Получаем path constraints для данной функции
path_constraints = path.state.solver.constraints

# Выводим path constraints
print("Path constraints for function at address 0x%x:" % func_addr)
for constraint in path_constraints:
    print(constraint)
state = proj.factory.blank_state(addr=entrypoint, add_options=angr.options.refs)
simgr = proj.factory.simulation_manager(state)
print("Done!")

# main_f=proj.factory.callable(0x140011A00)
# main_f.perform_call()
# pprint(state.history.descriptions.hardcopy)

# for gr in main_f.result_path_group:
#     print(gr)
# min_address = proj.loader.min_addr
# max_address = proj.loader.max_addr

# simgr.run()
# print(state.history.descriptions.hardcopy)
while len(simgr.active) > 0:
    simgr.step()
    for st in simgr.active:
        if min_address <= state.addr <= max_address:
            # print(hex(state.addr))
            print(state.solver.constraints)

# TODO: "run" every function and collect its' paths