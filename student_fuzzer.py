from types import FrameType
from fuzzingbook import GreyboxFuzzer as gbf
from fuzzingbook import Coverage as cv
from fuzzingbook import MutationFuzzer as mf

from typing import Callable, List, Optional, Set, Any, Tuple, Dict, Union

import traceback
import numpy as np
import time
import inspect

from bug import entrypoint
from bug import get_initial_corpus

## You can re-implement the coverage class to change how
## the fuzzer tracks new behavior in the SUT

class MyCoverage(cv.Coverage):
    not_offset = True
    # branch_coverage_empty = True
    program_lines = [""] + inspect.getsource(entrypoint).splitlines()
    # following array contains the line numbers where a block begins. Found by checking for control flow statements in source code
    branch_start_line_numbers = [2]
    for l in range(len(program_lines)):
        if 'if' in program_lines[l] or 'elif' in program_lines[l] or 'else' in program_lines[l] or 'case' in program_lines[l]:
            # append the line after control flow statement to show that that branch has been entered
            branch_start_line_numbers.append(l+1)

    def __init__(self) -> None:
        """Constructor"""
        self._trace: List[cv.Location] = []
        self.four_gram_storage = []
        self.branch_coverage_empty = True
        self.branch_coverage = []
        self.local_variables = {}
        self.four_gram_storage = []
        self.four_gram_counter = 0

    # TODO: Implement 4-gram branch coverage
    def traceit(self, frame: FrameType, event: str, arg: Any) -> Optional[Callable]:
        """Tracing function. To be overloaded in subclasses."""        
        if self.original_trace_function is not None:
            self.original_trace_function(frame, event, arg)
        
        dummy = 0
        if event == "line":
            function_name = frame.f_code.co_name
            lineno = frame.f_lineno
            if MyCoverage.not_offset and function_name == 'entrypoint':
                MyCoverage.not_offset = False
                offset = lineno - MyCoverage.branch_start_line_numbers[0]
                for i in range(len(MyCoverage.branch_start_line_numbers)):
                    MyCoverage.branch_start_line_numbers[i] += offset
            if function_name != '__exit__':  # avoid tracing ourselves:
                self._trace.append((function_name, lineno))
                if lineno in MyCoverage.branch_start_line_numbers:
                    self.four_gram_storage.append(lineno)
                    self.four_gram_counter += 1
                    if self.four_gram_counter == 4:
                        self.four_gram_counter = 0
                        self.branch_coverage.append(tuple(self.four_gram_storage))
                        self.four_gram_storage = []


            
        return self.traceit

    def coverage(self):
        """The set of executed lines, as (function_name, line_number) pairs"""
        if self.four_gram_counter > 0:
            while self.four_gram_counter < 4:
                self.four_gram_counter += 1
                self.four_gram_storage.append(0)
            self.branch_coverage.append(tuple(self.four_gram_storage))
            self.four_gram_counter = 0
            self.four_gram_storage = []

        # print(self.branch_coverage)
        return self.branch_coverage
        


## You can re-implement the runner class to change how
## the fuzzer tracks new behavior in the SUT

class MyFunctionCoverageRunner(mf.FunctionRunner):
    # _coverage = []
    # TODO: Check for which seed is used to generate test
    def run_function(self, inp: str) -> Any:
        with MyCoverage() as cov:
            try:
                result = super().run_function(inp)
            except Exception as exc:
                self._coverage = cov.coverage()
                raise exc

        self._coverage = cov.coverage()
        return result

    def coverage(self):
        return self._coverage


# class MyRunner(mf.FunctionRunner):
#
#     def run_function(self, inp):
#           <your implementation here>
#
#     def coverage(self):
#           <your implementation here>
#
#     etc...


## You can re-implement the fuzzer class to change your
## fuzzer's overall structure

# class MyFuzzer(gbf.GreyboxFuzzer):
#
#     def reset(self):
#           <your implementation here>
#
#     def run(self, runner: gbf.FunctionCoverageRunner):
#           <your implementation here>
#   etc...

## The Mutator and Schedule classes can also be extended or
## replaced by you to create your own fuzzer!


    
# When executed, this program should run your fuzzer for a very 
# large number of iterations. The benchmarking framework will cut 
# off the run after a maximum amount of time
#
# The `get_initial_corpus` and `entrypoint` functions will be provided
# by the benchmarking framework in a file called `bug.py` for each 
# benchmarking run. The framework will track whether or not the bug was
# found by your fuzzer -- no need to keep track of crashing inputs
if __name__ == "__main__":
    seed_inputs = get_initial_corpus()
    fast_schedule = gbf.AFLFastSchedule(5)
    line_runner = MyFunctionCoverageRunner(entrypoint)

    fast_fuzzer = gbf.CountingGreyboxFuzzer(seed_inputs, gbf.Mutator(), fast_schedule)
    fast_fuzzer.runs(line_runner, trials=999999999)
