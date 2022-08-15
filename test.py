from time import sleep

counter = 0

with open("testfile2") as file2:
    while True:
        print(counter)
        counter+=1
        with open("testfile","r+") as file:
            # file.write("0")
            file.read()
            pass
        # with open("testfile2","r+") as file:
        #     # file.write("1")
        #     file.readline()
        #     pass
        sleep(0.2)