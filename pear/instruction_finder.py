import re
from dataclasses import dataclass

@dataclass
class InstructionPattern:
    jt: list[str]

VAR_PATTERN = r"<[^>]*>"

def split_asm(asm: str) -> list[str]:
    '''
    Split an assembly instruction into tokens (mnemonic and operands).

    For example, an instruction like:
        "add x0, x1, x2"
    is split into:
        ["add", "x0", "x1", "x2"]

    :param asm: Single assembly instruction as a string.
    :returns: List of tokens, with the first token representing the mnemonic
              and the subsequent tokens representing the operands.
    '''
    spl = asm.split(' ')
    ins = spl[0]
    op = [x.strip() for x in (asm[len(ins):]).split(',')]
    split = [ins] + op
    return split

def substitute_pattern(pattern: list[str],
                       values: dict[str,str]) -> list[str]:
    '''
    Substitute known variable placeholders in a pattern with their
    corresponding values.

    I.e If a pattern element contains a placeholder like "<r1>" and the
    dictionary 'values' has {"<r1>": "x1"}, then "<r1>" will be replaced with
    "x1" in the result. Unmatched placeholders remain as-is in the output.

    :param pattern: list of tokens, potentially containing placeholders.
    :param values: Dict of placeholders to their string replacements
    :returns: A new list of tokens with placeholders substituted.
    '''
    # Create new pattern by substituting known values into the pattern
    subst_pattern = []
    for p in pattern:
        match = False
        for var, value in values.items():
            if var in p:
                match = True
                subst_pattern.append(p.replace(var, value))
                break
        if not match:
            subst_pattern.append(p)
    return subst_pattern

def match_pattern(asm: list[str],
                  pattern: list[str],
                  values: dict[str,str]) -> bool:
    '''
    Attempt to match a tokenized assembly instruction against a pattern.

    The pattern may include:
        - Wildcards: "*"
          which match anything in their position.
        - Partial wildcards: "foo*", "*foo", "fo*o"
          which must match the specified prefix/suffix but can have any
          substring in between.
        - Variable placeholders: "<r1>", "<label>", etc.
          which, if matching succeeds, will be stored in 'values'.

    If a variable placeholder in 'pattern' is matched, 'values' is updated in
    place with the mapping from that placeholder to the actual token. If the
    pattern fully matches, this function returns True; otherwise, it returns
    False.

    :param asm: Token of the asm instruction to match
    :param pattern: Pattern to match against asm instruction
    :param values: A dictionary used to store or update placeholder-to-value
        mappings. This can also contain pre-existing mappings that must not be
        contradicted by the match.
    :returns: True if the asm instruction matches the pattern; False otherwise.
    '''
    # Set pattern with already known values
    s_pattern = substitute_pattern(pattern, values)
    
    # Pattern cannot match asm if they are not the same length
    if len(s_pattern) != len(asm):
        return False

    new_val = {}
    new_val.update(values)
    for ins, pat in zip(asm, s_pattern):
        if pat == '*':
            # full wildcard, anything goes
            continue
        elif '*' in pat:
            # *foo, foo*, and fo*o cases
            p_start, p_end = pat.split('*')
            if not (ins.startswith(p_start) and ins.endswith(p_end)):
                return False
        elif '<' in pat:
            # variable cases (<var>a, a<var>, a<var>b)
            v = re.findall(VAR_PATTERN, pat)
            assert len(v) == 1, "too many variables in instruction/operand"
            var = v[0]
            p_start, p_end = pat.split(var)
            if not (ins.startswith(p_start) and ins.endswith(p_end)):
                return False
            # find and set var
            value = ins[len(p_start):len(ins)-len(p_end)]
            new_val[var] = value
        elif pat != ins:
            # direct match case (not matched)
            return False

    # fully matched, update values
    values.update(new_val)
    return True
            
def find_asm_pattern(asm: list[str], pattern: list[str]) -> list[list[int]]:
    '''
    Search for all occurrences of a multi-instruction pattern in a list of
    assembly instructions (represented as strings).
    THIS WILL NOT ALWAYS FIND HEAVILY INTERLEAVED MATCHES.

    Each line in the 'pattern' is itself an assembly string that may include:
        - Placeholders like "<r1>", "<label>". Registers must be <rX>, X any num
        - Wildcards ("*").
        - Partial wildcards (e.g., "ldr*", "*foo").

    :param asm: A list of assembly instructions as strings (e.g., ["add x0, x1,
        x2", "ldr x3, [x0]"]).
    :param pattern: A list of pattern strings (e.g., ["adrp <r1>,
        <jump_table>", "add <r1>, <r1>, :lo12:<jump_table>"]).
    :returns: A list of matches. Each match is a list of indices into 'asm'
        representing the lines that matched the pattern in order. For example,
        [[10, 11, 12], [20, 21, 22]] would mean the pattern was found at
        instructions 10..12 and 20..22 in 'asm'.
    '''
    # pattern/asm lines are in format: "ins op1, op2, op3, ..."
    # convert this into a list: [ins, op1, op2, ...[
    pat = [split_asm(x) for x in pattern]
    
    # List of indices of matches. [ [1,2,3], [11, 15, 16] ]
    matches: list[list[int]] = []

    # Indices of possible current match
    match: list[int] = []

    # Set values of current match
    # <var>: value
    values: dict[str, str] = {}

    # index of pattern we are looking for 
    pat_i = 0

    # start of current patter we are looking at
    curr_pat_start = -1

    # index into current asm
    i = 0

    def reset_search_state():
        ''' End current match '''
        nonlocal match, values, pat_i, i, curr_pat_start
        match = []
        values = {}
        pat_i = 0
        i = curr_pat_start # will be incremented at end of loop
        curr_pat_start = -1

    while i < len(asm):
        split = split_asm(asm[i])

        # Check match
        if match_pattern(split, pat[pat_i], values):
            if pat_i == 0:
                # On first match, set start match location
                curr_pat_start = i
            # add index to match set
            match.append(i)
            pat_i += 1
            if pat_i == len(pattern):
                # Finished pattern. Save match and look for next one
                matches.append(match)
                reset_search_state()
        else:
            # Check liveness
            # As soon as a register variable gets a value, any further use of
            # that value beyond specified in the pattern breaks the match
            # I.e if <r1> is set to x1, and x1 is used in a non-matching
            # instruction, we cancel the current match.
            cancelled = False
            for var in values:
                if var.startswith('<r') and var in values:
                    live_reg = values[var]
                    for x in split:
                        if x == live_reg:
                            # Live register used, cancel current match
                            reset_search_state()
                            cancelled = True
                            break
                    if cancelled:
                        break

        if i+1 == len(asm) and curr_pat_start != -1:
            # Reached EOF mid-match, cancel match
            reset_search_state()
        i += 1

    return matches
