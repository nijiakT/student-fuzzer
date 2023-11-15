
def get_initial_corpus():
    return ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]


def entrypoint(s):
    x = 0
    cond = False

    if len(s) > 15 and s[10] == 'a':
        x = 1
    
    if len(s) > 15 and s[10] == 'b':
        x = 2

    
    if x == 0:
        if s[0] == 'o':
            if s[1] == 'k':
                cond = True
       
    if cond and s[2] == 'b':
        if s[4] == 'u':
            if s[6] == 'g':
                if s[8] == '!':
                    # print("Bug reached")
                    exit(219)
    
