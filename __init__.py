from binaryninja import *
from pprint import pprint as puts
import sys
import highlight


INDENT = "    "
STRINGS = []

def output(i, count, bv, func):
    o = [str(i.instr_index).ljust(4), "0x{:x}    ".format(i.address), (INDENT*count)]

    # print i.tokens
    if i.operation == LLIL_IF:
        o.append('if ')
        o.append(str(i.condition) + ': ')
    else:
        comments = []
        if i.operation == LLIL_PUSH and i.src.operation == LLIL_REG:
            try:  ## temp0.d = eax ^ [gsbase + 0x14].d
                c = str(func.get_reg_value_at(bv.arch, i.address, str(i.src)))
                if not "undetermined" in c:
                    comments.append(str(i.src)+":"+c)
            except KeyError:
                pass

        if i.operation_name.startswith('LLIL_SET_REG'):
            try: ## temp0.d = eax ^ [gsbase + 0x14].d
                c = str(func.get_reg_value_at(bv.arch, i.address, str(i.dest)))
                if not "undetermined" in c:
                    comments.append(str(i.dest)+":"+c)
            except KeyError:
                pass

        for t in i.tokens:
            if str(t).startswith('0x'):
                address = int(str(t), 16)
                sym = bv.get_symbol_at(address)
                if sym:
                    comments.append(str(t))
                    t = sym.full_name
                else:
                    for s in STRINGS:
                        if s.start == address:
                            comments.append(str(t))
                            t = repr(bv.read(s.start, s.length))
            o.append(str(t))
        if comments:
            o.append(" ## " + " ".join(comments))

    # "".join([str(z) for z in i.tokens])
    print "".join(o)
    return o

def process_blocks(bv, func, blocks, mapping, data, count=0):
    if type(blocks) == list:
        b = blocks[0]
    else:
        b = blocks

    for i in b:
        block_address = b.start
        # print i.tokens
        if i.operation == LLIL_IF:
            data.append(output(i, count, bv, func))
            true_block = mapping[i.true]
            if i.true > block_address:
                process_blocks(bv, func, true_block, mapping, data, count=count+1)
            else:
                o = str(i.instr_index).ljust(4), "0x{:x}    ".format(i.address), (INDENT*(count+1)), "goto ", str(i.true)
                print "".join(o)
                data.append(o)

            o = str(i.instr_index).ljust(4), "0x{:x}    ".format(i.address), (INDENT*count), "else:"
            print "".join(o)
            data.append(o)

            false_block = mapping[i.false]
            if i.false > block_address:
                process_blocks(bv, func, false_block, mapping, data, count=count+1)
            else:
                o = str(i.instr_index).ljust(4), "0x{:x}    ".format(i.address), (INDENT*(count+1)), "goto ", str(i.false)
                print "".join(o)
                data.append(o)
            return

        if i.operation == LLIL_GOTO:
            data.append(output(i, count, bv, func))
            goto_block = mapping[i.dest]
            if i.dest > block_address:
                process_blocks(bv, func, goto_block, mapping, data, count=count)
            return

        data.append(output(i, count, bv, func))


def process_llil(llil, bv, func):
    global STRINGS
    mapping = {}
    blocks = []
    for bb in llil:
        mapping[bb.start] = bb
        blocks.append(bb)
    print mapping
    data = []
    STRINGS = bv.get_strings()
    process_blocks(bv, func, blocks, mapping, data)
    return data

def get_llil(func):
    return func.low_level_il

def open_file(filename, update_analysis=True):
    view = BinaryView.open(filename)
    if view is None:
        return None
    for available in view.available_view_types:
        if available.name != "Raw":
            bv = BinaryViewType[available.name].open(filename)
            if update_analysis:
                bv.update_analysis_and_wait()
            return bv
    return None

def load_linear_il(bv, func):
    print bv, func
    llil = get_llil(func)
    data = process_llil(llil, bv, func)
    text = "\n".join(["".join(line) for line in data])
    print repr(text)
    classified_text = highlight.analyze_python(text)
    html = highlight.build_html_page(classified_text)

    bv.show_html_report(func.name, html)


if __name__ == '__main__':
    bv = open_file(sys.argv[1])
    bv.update_analysis_and_wait()
    func = bv.get_functions_at(0x8048fd8)[0]
    llil = get_llil(func)
    process_llil(llil, bv, func)
    # import IPython
    # IPython.embed()
else:
    PluginCommand.register_for_function("Linear IL View", "Shows a Linear IL View", load_linear_il)