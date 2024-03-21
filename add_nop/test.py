import gtirb_rewriting.driver
from gtirb_rewriting import *
import argparse
import gtirb

class CallFunctionPatch(Patch):
    '''
    Call function with 16 byte stack alignment while preserving registers
    DOES NOT PRESERVE FLOAT REGISTERS
    '''
    def __init__(self, func, save_stack=0x100):
        self._func = func
        self._save_stack= save_stack
        super().__init__(Constraints(x86_syntax=X86Syntax.INTEL))

    def get_asm(self, insertion_context: InsertionContext) -> str: # pyright: ignore
        return f'''
            sub     rsp, {hex(self._save_stack)}
           
            pushfq
            push    rax
            push    rcx
            push    rdx
            push    rsi
            push    rdi
            push    r8
            push    r9
            push    r10
            push    r11
            push    rax

            mov     rax, rsp
            lea     rsp, [rsp - 0x80]
            and     rsp, 0xfffffffffffffff0
            push    rax
            push    rax

            call {self._func}

            pop     rax
            mov     rsp, rax

            pop     rax
            pop     r11
            pop     r10
            pop     r9
            pop     r8
            pop     rdi
            pop     rsi
            pop     rdx
            pop     rcx
            pop     rax
            popfq

            add rsp, {hex(self._save_stack)}
        '''

class MyPass(Pass):
    def __init__(self, num):
        self.num = num
        super().__init__()

    def begin_module(self, module, functions, context: RewritingContext) -> None: #pyright: ignore

        print('----------------------------------------')

        a = "pushf\npopf\n" * self.num

        context.register_insert(
            SingleBlockScope(module.entry_point, BlockPosition.ENTRY),
            Patch.from_function(lambda _: f'''
                {a}
            ''', Constraints(x86_syntax=X86Syntax.INTEL))
        )

        print('----------------------------------------')

class MyPass2(Pass):
    def begin_module(self, module, functions, context: RewritingContext) -> None: #pyright: ignore

        print('----------------------------------------')

        context.register_insert(
            SingleBlockScope(module.entry_point, BlockPosition.ENTRY),
            Patch.from_function(lambda _: f'''
                push rdi
                pop rdi
            ''', Constraints(x86_syntax=X86Syntax.INTEL))
        )

        print('----------------------------------------')

class TestPass(Pass):
    def begin_module(self, module, functions, context: RewritingContext) -> None: #pyright: ignore

        print('----------------------------------------')

        context.register_insert(
            SingleBlockScope(module.entry_point, BlockPosition.ENTRY),
            Patch.from_function(lambda _: f'''
                push rdi
                pop rdi
            ''', Constraints(x86_syntax=X86Syntax.INTEL))
        )

        print('----------------------------------------')

def main():
    parser = argparse.ArgumentParser(description="testing")
    parser.add_argument('infile', help="Path to the input file.")
    parser.add_argument('outfile', help="Path to the input file.")

    args = parser.parse_args()

    print("Loading IR ...")
    ir = gtirb.IR.load_protobuf(args.infile)

    print("Modifying ...")
    manager = PassManager()
    manager.add(TestPass())
    manager.run(ir)

    print("Outputting ...")
    ir.save_protobuf(args.outfile)

if __name__ == "__main__":
    #gtirb_rewriting.driver.main(MyPass)

    main()

