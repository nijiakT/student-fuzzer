import os, time, random, string, numpy

def benchmark_fuzzer(fuzzer_path, num_iterations, seed_inputs):
    try:
        i = 0
        seconds = [-1 for x in range(num_iterations)]
        while i < num_iterations:
            input_i = seed_inputs[i]
            # benchmarking per seed input
            start = time.time()
            wait_status = os.system(f'python3 {fuzzer_path} {input_i}')
            end = time.time()
            # print(exit_code)
            exit_code = os.waitstatus_to_exitcode(wait_status)
            # bug is found if exit code 219 is given (as defined in my buggy program)
            if exit_code == 219:
                total_time = end - start
                seconds[i] = total_time
            i += 1
        print(seconds)
        found_seconds = [s for s in seconds if s != -1]
        file_name = fuzzer_path[:-3] + ".csv"
        print(file_name + ": ")
        print(str(len(found_seconds)) + " bugs found")
        if len(found_seconds) > 0:
            mean = sum(found_seconds) / len(found_seconds) 
            var = sum((i - mean) ** 2 for i in found_seconds) / len(found_seconds)
            print("Mean: " + str(mean))
            print("Variance: " + str(var))

            found_seconds.append(mean)
            found_seconds.append(var)
        
        # save benchmarking data to csv file
        np_seconds = numpy.array(found_seconds)
        numpy.savetxt(file_name, np_seconds, delimiter=",")
    except:
        # print(e)
        print(f'Path invalid')

if __name__ == "__main__":
    # run 100 trials
    num_iterations = 100
    random.seed(10)
    seed_inputs = []
    for i in range(num_iterations):
        input_i = ''.join(random.choices(string.ascii_lowercase, k=20))
        seed_inputs.append(input_i)
    benchmark_fuzzer('baseline_fuzzer_benchmarking.py', num_iterations, seed_inputs)
    benchmark_fuzzer('student_fuzzer_benchmarking.py', num_iterations, seed_inputs)