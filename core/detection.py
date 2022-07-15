from utils import *
import sys


if __name__=='__main__':

    
    if len(sys.argv) == 1 or len(sys.argv) > 3 or sys.argv[1].strip() == '--help' or (sys.argv[1].strip() != '--single' and sys.argv[1].strip() != '--range'):
        usage()
        sys.exit(1)

    if len(sys.argv) > 2 and sys.argv[1].strip() == '--single':

        if sys.argv[2].strip() == '':
            usage()
            sys.exit(1)
        
        if not checkSingleFormat(sys.argv[2].strip()):
            usage()
            sys.exit(1)

        createDatabase()

        if deviceInDatabase(sys.argv[2].strip()):
            option = int(input("""\nDevice {} has already been analyzed. What do you wanna do?:
                                \n  1 -> Repeat the detection and remove the existent device
                                \n  2 -> Repeat the detection and keep the existent device
                                \n  3 -> Exit
                                \nChoose option 1, 2 or 3: """.format(sys.argv[2].strip())))
            if option == 1:
                removeDeviceFromDatabase(sys.argv[2].strip())
            
            elif option == 3:
                sys.exit(0)

        singleDeviceDetection(sys.argv[2].strip())

    if len(sys.argv) > 2 and sys.argv[1].strip() == '--range':

        if sys.argv[2].strip() == '':
            usage()
            sys.exit(1)

        if not checkRangeFormat(sys.argv[2].strip()):
            usage()
            sys.exit(1)

        multipleDevicesDetection(sys.argv[2].strip())
    
    usage()
    sys.exit(1)

    