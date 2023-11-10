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
    # this code implements my version of the 4-gram branch coverage, with two additions:
    # (1) the final nested if checker, that helps in finding bugs hidden inside nested ifs by
    # keeping track of the final lines of code (before the last branch) reached by the algorithm, and
    # (2) the nested degree weights. If a doubly (or more) nested if is entered, the algorithm
    # detects this and adds a "weight" to the path (in the form of negative numbers), to encourage
    # the coverage to be seen as interesting
    not_offset = True
    # branch_coverage_empty = True
    program_lines = [""] + inspect.getsource(entrypoint).splitlines()
    # following array contains the line numbers where a block begins. Found by checking for control flow statements in source code
    branch_start_line_numbers = [2]
    for l in range(len(program_lines)):
        if 'if' in program_lines[l] or 'elif' in program_lines[l] or 'else' in program_lines[l] or 'case' in program_lines[l]:
            # append the line after control flow statement to show that that branch has been entered
            branch_start_line_numbers.append(l+1)
    final_branch_start_line = 0
    nesting_degree_checker = {}
    nesting_degree_counter = -1
    new_nesting_degree = False

    def __init__(self) -> None:
        """Constructor"""
        self._trace: List[cv.Location] = []
        self.branch_coverage = []
        self.four_gram_storage = []
        self.four_gram_counter = 0
        self.final_nest_checker = []
        self.final_nest_counter = 0
        self.nesting_degree_payload = []
        self.branch_hit = []

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
                # self._trace.append((function_name, lineno))
                if lineno < MyCoverage.branch_start_line_numbers[-1]:
                    self.final_nest_checker.append(lineno)
                    self.final_nest_counter += 1
                    if self.final_nest_counter == 5:
                        self.final_nest_counter = 0
                        self.final_nest_checker = []
                if (lineno - 1) in MyCoverage.branch_start_line_numbers:
                    self.branch_hit.append(lineno - 1)

                if lineno in MyCoverage.branch_start_line_numbers:
                    self.four_gram_storage.append(lineno)
                    self.four_gram_counter += 1
                    if lineno not in MyCoverage.nesting_degree_checker:
                        MyCoverage.nesting_degree_checker[lineno] = MyCoverage.nesting_degree_counter
                        MyCoverage.new_nesting_degree = True

                    payload = MyCoverage.nesting_degree_checker[lineno]
                    self.nesting_degree_payload.append(tuple(range(payload, payload*2, -1)))
                    if self.four_gram_counter == 4:
                        self.four_gram_counter = 0
                        self.branch_coverage.append(tuple(self.four_gram_storage))
                        self.four_gram_storage = []

            if function_name == "run_function" and MyCoverage.new_nesting_degree:
                MyCoverage.new_nesting_degree = False
                MyCoverage.nesting_degree_counter *= 2
   
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

        final_nested_tuple = tuple((self.final_nest_checker))
        # cov = self.branch_coverage + [final_nested_tuple] + (self.nesting_degree_payload)
        cov = self.branch_coverage + [final_nested_tuple]
        if len(self.nesting_degree_payload) > 2:
            cov += self.nesting_degree_payload[-4:]
        # print(cov)
        return cov
        


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
