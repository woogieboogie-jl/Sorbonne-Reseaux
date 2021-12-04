import os
import datalink
import hexdecoder
import iohandler

def initiate():
    while True:
        path_input = input("input working directory, press enter if you wish to analyze in current directory...")
        try:
            if path_input:
                os.chdir(path_input)
            text_list = list(filter(lambda x: ".txt" in x, os.listdir()))
            print("----------AVALIABLE TEXT FILES-----------")
            for file in text_list:
                print(file)
            
            while True:
                file_input =input("input filename...")
                path = os.path.abspath(os.getcwd()) + "/" + file_input
                try:
                    file = iohandler.fileinput(path)
                    return file
                except FileNotFoundError:
                    print("FILE NOT FOUND! PLEASE TYPE THE RIGHT FILENAME!...")  
                except IsADirectoryError:
                    print("INPUT FILENAME, NOT DIRECTORY!...")
    
            
        except FileNotFoundError:
            print("WRONG DIRECTORY! PLEASE TYPE THE RIGHT DIRECTORY!...")
            continue

        

def parser(hex_list):
    hex_list_filtered = hexdecoder.filterData(hex_list)
    hex_list_seperated = hexdecoder.splitTrace(hex_list_filtered)
    hex_list_parsed = hexdecoder.offsetSeq(hex_list_seperated)
    return hex_list_parsed



def main():
    hex_list = initiate()
    hex_parsed = parser(hex_list)
    print(hex_parsed)


if __name__ == "__main__":
    main()