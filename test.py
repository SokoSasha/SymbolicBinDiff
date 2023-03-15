import angr
import logging
from idautils import *
from idaapi import *
from idc import *

m_state = None
state_manager = None

class FuncInfo():
    def __init__(self, name, start, end):
        self.__func_name = name
        self.__start = start
        self.__end = end
        self.__constraints = set()
        self.__calls = dict()
        self.__reps = dict()

    @property
    def name(self):
        return self.__func_name

    @property
    def start(self):
        return self.__start

    @property
    def end(self):
        return self.__end

    def __str__(self):
        output = f"Function {self.__func_name} [{hex(self.__start)} : {hex(self.__end)}]\nConstraints:\n"
        for con in self.__constraints:
            output+=f"{con}\n"
        output+="Calls:\n"
        for calll in self.__calls.items():
            output+=f"{hex(calll[0])} {calll[1]}\n"
        output+="Reps:\n"
        for rep in self.__reps.items():
            output+=(f"{hex(rep[0])}: len = {rep[1]}")
        return output

    def __repr__(self):
        print(self)

    # Собираем данные символьным исполнением
    def collectConstraints(self):
        print(f"\nDoing {self.name}...")
        m_state = proj.factory.blank_state(addr=self.__start)
        state_manager = proj.factory.simgr(m_state)

        def __skip_hook(skip_name):
            print(f"Skipping {skip_name}...")

        # Расставляем хуки
        for skip in self.__calls:
            proj.hook(skip, __skip_hook(self.__calls[skip]['name']), length=self.__calls[skip]['skip_len'])

        class MyHook(angr.SimProcedure):
            def run(self):
                print("Short rep...")
                self.state.regs.ecx = 0x1

        for rep in self.__reps:
            proj.hook(rep, MyHook(), length=self.__reps[rep])

        # Пошагово выполняем программу и сохраняем необходимые данные
        while len(state_manager.active) > 0:
            state_manager.step()
            for state in state_manager.active:
                if state.scratch.ins_addr > fea.end:
                    break
                for con in state.solver.constraints:
                    # print(con)
                    self.__constraints.add(str(con))

        # Удаляем на всякий случай
        del state_manager
        del m_state

    # Находим самую первую push инструкцию перед call
    def findFirstPush(self, addr):
        r_addr = addr
        current_ea = prev_head(addr, self.__start)
        while current_ea > self.__start:
            mnem = print_insn_mnem(current_ea)
            if mnem == 'push':
                r_addr = current_ea
            else:
                break
        return r_addr

    # Находим все вызовы других функции внутри текущей функции
    def findCalls(self):
        current_ea = self.__start
        while current_ea < self.__end:
            mnemonic = print_insn_mnem(current_ea)
            if mnemonic == 'call':
                c_name = print_operand(current_ea, 0)
                c_start = self.findFirstPush(current_ea)
                self.__calls[c_start] = {'name': c_name, 'skip_len': next_head(current_ea) - c_start}
            current_ea = next_head(current_ea, self.__end)

    # Находим все инструкции rep
    def findRep(self):
        print("Find rep...")
        current_ea = self.__start
        while current_ea < self.__end:
            mnem = generate_disasm_line(current_ea, 0)
            if 'rep' in mnem:
                n_head = next_head(current_ea, self.__end)
                self.__reps[current_ea] = n_head - current_ea
            current_ea = next_head(current_ea, self.__end)

########################################################################################################
def get_func_by_name(func_list, name):
    for func in func_list:
        if func.name == name:
            return func
    print("No such function")

def collectFuncs():
    print("Collecting functions...")
    funcsList = []
    for ea in Functions():
        if not get_func_flags(ea) & (FUNC_LIB | FUNC_THUNK | FUNC_FAR | FUNC_NORET):
            end_ea = get_func_attr(ea, FUNCATTR_END) - 0x1  # Конец функции
            name_ea = ida_funcs.get_func_name(ea)  # Имя функции
            funcsList.append(FuncInfo(name_ea, ea, end_ea))
    print("Done!")
    return funcsList

if __name__ == '__main__':
    proj = angr.Project(get_input_file_path(), load_options={'auto_load_libs': False},
                        main_opts={'base_addr': get_imagebase()})

    # Убираем WARNING сообщения
    logger = logging.getLogger('angr').setLevel(logging.ERROR)

    funcs = collectFuncs()

    # fea = get_func_by_name(funcs, "?func@@YAXH@Z")
    # findCalls(fea)

    for fea in funcs:
        fea.findCalls()
        fea.findRep()

    for fea in funcs:
        fea.collectConstraints()

    for fea in funcs:
        print(fea)