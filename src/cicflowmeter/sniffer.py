import argparse

from scapy.sendrecv import AsyncSniffer

from .flow_session import generate_session_class

import threading, time

def create_sniffer(
    input_file, input_interface, output_mode, output_file
):
    assert (input_file is None) ^ (input_interface is None)
    
    NewFlowSession = generate_session_class(output_mode, output_file)
    
    if input_file is not None:
        return AsyncSniffer(
            offline=input_file,
            filter="ip and tcp",
            prn=None,
            session=NewFlowSession,
            store=False,
        )
    else:
        return AsyncSniffer(
            iface=input_interface,
            filter="ip and tcp",
            prn=None,
            session=NewFlowSession,
            store=False,
        )

def timelimit(sniffer):
    if sniffer.running: 
        x = sniffer.stop()
    print("\033[31mReached the time limit!\033[0m")
    
def main():
    parser = argparse.ArgumentParser()
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "-i",
        "--interface",
        action="store",
        dest="input_interface",
        help="capture online data from INPUT_INTERFACE",
    )

    input_group.add_argument(
        "-f",
        "--file",
        action="store",
        dest="input_file",
        help="capture offline data from INPUT_FILE",
    )
    
    parameter_group = parser.add_mutually_exclusive_group(required=False)
    parameter_group.add_argument(
        "-t",
        "--timelimit",
        action="store",
        dest="limit",
        default=600,
        type=int,
        help="the specified capture time (default is 10 mins)",
    )

    output_group = parser.add_mutually_exclusive_group(required=True)
    output_group.add_argument(
        "-c",
        "--csv",
        "--flow",
        action="store_const",
        const="flow",
        dest="output_mode",
        help="output flows as csv",
    )
    
    output_group.add_argument(
        "-m",
        "--mod",
        action="store_const",
        const="predict",
        dest="output_mode",
        help="model used to predict the flow is benign or malicious",
    )

    parser.add_argument(
        "output",
        help="output file name (in flow mode) or predict result (in predict mode)",
    )

    args = parser.parse_args()
    sniffer = create_sniffer(
        args.input_file,
        args.input_interface,
        args.output_mode,
        args.output,
    )
    #if args.limit > 600 or args.limit < 1:
    #    raise ValueError("\033[31mthe range of timelimit is (0,600]!\033[0m")

    if args.output_mode == "flow":
        print("\033[32mIn flow mode\033[0m")
        print("Start to generate csv file!")
        print("----------------------------------")
    else:
        print("\033[32mIn predict mode\033[0m")
        print("Detector started!")
        print("----------------------------------")

    if args.input_file is None:
        t = threading.Timer(args.limit, timelimit, (sniffer,))
        t.start()
        sniffer.start()

        try:
            sniffer.join()
            if t.is_alive():
                t.cancel()
                t.join()
    
        except KeyboardInterrupt:
            print("\033[31mInterrupted by user!\033[0m")
            t.cancel()
            t.join()
            x = sniffer.stop()
            while sniffer.results is None:
                time.sleep(1)
    
        finally:
            sniffer.join()
            if t.is_alive():
                t.cancel()
                t.join()

    elif args.input_file is not None:
        sniffer.start()

        try:
            sniffer.join()

        except KeyboardInterrupt:
            print("\033[31mInterrupted by user!\033[0m")
            x = sniffer.stop()
            while sniffer.results is None:
                time.sleep(1)

        finally:
            sniffer.join()

if __name__ == "__main__":
    main()
