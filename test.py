import angr
import logging
import re
from idautils import *
from idaapi import *
from idc import *

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

    @property
    def constr(self):
        return self.__constraints

    @property
    def calls(self):
        return self.__calls

    @property
    def reps(self):
        return self.__reps

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
        m_state = proj.factory.blank_state(addr=self.__start)
        state_manager = proj.factory.simgr(m_state)

        # Пустой хук на call
        def __skip_hook(skip_name):
            # print(f"Skipping {skip_name}...")
            pass

        # Хук на rep, сокращающий его выполнение до 1 цикла
        class MyHook(angr.SimProcedure):
            def run(self):
                # print("Short rep...")
                self.state.regs.ecx = 0x1

        # Расставляем хуки
        for skip in self.__calls:
            proj.hook(skip, __skip_hook(self.__calls[skip]['name']), length=self.__calls[skip]['skip_len'])

        for rep in self.__reps:
            proj.hook(rep, MyHook(), length=self.__reps[rep])

        # Находим места в constratints, где присутствует сравнение двух символьных переменных.
        # Подобные сравнения приводят к долгой обработке
        def findError(constr):
            ops = ['==', '!=', '>=', '>', '<=', '<']

            str_con = str(constr)[1:-1]
            fin = [item.strip() for item in re.split('&&|\\|\\|', str_con) if item]

            def stripVar(varia):
                varia = varia.replace("{UNINITIALIZED}", '')
                varia = varia.replace('(', '')
                varia = varia.replace(')', '')
                varia = re.sub(r'\[[^]]+\]', '', varia)
                return varia

            for f in fin:
                # pos = next((i for i, c in enumerate(f) if c in ops), None)
                for op in ops:
                    if (pos := f.find(op)) != -1:
                        break
                if pos != None and '{UNINITIALIZED}' in f[:pos] and '{UNINITIALIZED}' in f[pos:]:
                    left = {stripVar(p) for p in f[:pos].split() if '{UNINITIALIZED}' in p}
                    right = {stripVar(p) for p in f[pos:].split() if '{UNINITIALIZED}' in p}
                    return left | right

            return None

        # Пошагово выполняем программу и сохраняем необходимые данные
        while state_manager.active:
            state_manager.step()
            for state in state_manager.active:
                for con in state.solver.constraints:
                    if '{UNINITIALIZED}' in str(con):
                        if (var:=findError(con)) != None:
                            change = next(filter(lambda lst: next(iter(var)) in str(lst[1]), state.solver.get_variables()), None)[0]
                            print(f"{change} is {type(change)}")
                            # print(f"{change[0]} {change[1]}")
                            # TODO: Как изменить переменную change??????
                            print(x:=state.solver.get_variables(change[0], change[1]))
                            for y in x:
                                print(y)
                                state.solver.eval(y, 1)
                                print(state.solver.eval(y))
                            raise Exception("Comparing two uninitialized variables")

                    self.__constraints.add(str(con))

        # Удаляем на всякий случай
        del state_manager
        del m_state

    # Находим самую первую push инструкцию перед call
    def __findFirstPush(self, addr):
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
    def findSkips(self):
        current_ea = self.__start
        while current_ea < self.__end:
            mnemonic = str(generate_disasm_line(current_ea, 0)).split(' ')[0]
            if mnemonic == 'call':
                c_name = print_operand(current_ea, 0)
                c_start = self.__findFirstPush(current_ea)
                self.__calls[c_start] = {'name': c_name, 'skip_len': next_head(current_ea) - c_start}

            if 'rep' in mnemonic:
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
    funcsList = []
    for ea in Functions():
        if not get_func_flags(ea) & (FUNC_LIB | FUNC_THUNK | FUNC_FAR | FUNC_NORET):
            end_ea = get_func_attr(ea, FUNCATTR_END) - 0x1  # Конец функции
            name_ea = ida_funcs.get_func_name(ea)  # Имя функции
            funcsList.append(FuncInfo(name_ea, ea, end_ea))
    return funcsList

if __name__ == '__main__':
    print("Start...")
    proj = angr.Project(get_input_file_path(), load_options={'auto_load_libs': False},
                        main_opts={'base_addr': get_imagebase()})

    # Убираем WARNING сообщения
    logger = logging.getLogger('angr').setLevel(logging.ERROR)

    funcs = collectFuncs()

    # fea = get_func_by_name(funcs, "_RTC_AllocaHelper")
    # fea.findRep()

    for fea in funcs:
        fea.findSkips()

    for fea in funcs:
        fea.collectConstraints()
    #
    # for fea in funcs:
    #     print(fea)
