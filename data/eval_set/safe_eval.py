def compute(raw_value):
    # only an integer literal can ever reach the interpreter
    return eval(str(int(raw_value)))
