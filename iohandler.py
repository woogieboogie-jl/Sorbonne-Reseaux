def fileinput(path = "testinput.txt"):
    file = open(path, 'r').read().replace("\n", " ")
    return file.lower().split(" ")


def fileoutput(output, path = "testoutput.txt"):
    with open(path,'w') as file:
        file.write(output)