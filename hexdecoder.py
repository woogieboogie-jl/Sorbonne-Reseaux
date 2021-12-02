

# check if given String / Hex data is hexadecimal or not, else return False
def isHex(hex_string):
    hex_list = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]
    try:
        test_byte = [int(halfbyte, 16) for halfbyte in hex_string] 
        for halfbyte in test_byte:
            if halfbyte not in hex_list:
                return False
        return True
    except ValueError:
        return False

# checks if hex_String is either 1.length more than 2 / 2.each letter is hexadecimal.
def isOffset(hex_String):
    if len(hex_String) >= 3:
        return False if isHex(hex_String) is False else True
    else:
        return False 

def parserTrace(hex_dump):
    trace_list = []
    cnt = 0
    trace = []
    found_offset = False
    for element in hex_dump:
        if found_offset and isOffset(element) and int(element,16) ==0:
            trace_list.append(trace)
            trace = []
            cnt += 1
        if isOffset(element) and int(element,16) == 0:
            found_offset = True
        if found_offset and isHex(element):
            trace.append(element)
    trace_list.append(trace) 

    return trace_list


# def parser_inner(trace_list):
    # line_list = [line.split(" ") for line in read_list]
    # hex_dict = {}
    # pre_offset = ""
    # for line in line_list:

    #     if isOffset(element):
    #         if int(element, 16) == 0:
    #             pre_offset = element
    #         else:
                
        
        

    #         hex_dict[f"{pre_offset}"]

        
    # return parsed


# returns list of decimal numbers from list of hexadecimal Strings
def ParsedtoDeclist(parsed_list):
    return [int(byte,16) for byte in parsed_list]

# number -> hex String
def formatHex(numb):
    return format(numb,"x")

# number -> dec String
def formatDec(numb):
    return str(numb)

# converts list of hexadecimal numbers to String (Hex)
def listToStringHex(list):
    list = [formatHex(numb) for numb in list]
    return " ".join(list)

# converts list of decimal numbers to String (Dec) 
def listToStringDec(list):
    list = [formatDec(numb) for numb in list]
    return " ".join(list)

