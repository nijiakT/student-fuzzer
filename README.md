# Student Fuzzer
CS5219 Assignment 2 Submission for Teo Kai Jin (A0285642X)

## Description
Repository has a similar structure to the initial template; contains README, LICENSE, Dockerfile, requirements.txt, examples directory, bug.py, experiments directory and student_fuzzer.py

student_fuzzer.py contains my implementation of a fuzzer that uses four-gram branch coverage, with the addition of a final nested if checker to aid in finding bugs hiding in nested ifs.

The experiments directory contains bug.py, which is the motivating example "buggy" Python program that I use to evaluate the performance of my fuzzer against the baseline fuzzer. The bug is represented by the line "exit(219)", hidden inside a nested if at the end of the program. This directory also contains the experiment.py script, which I used to complete my benchmarking. The time taken to find the bug (per successful fuzzing) is stored inside the respective csv files, as well as the mean and variance of time taken. The mean and variance are the last two values in the csv files.

The experiments directory also contains the data directory, which contain the csv files I obtained by running experiment.py locally. baseline_fuzzer_benchmarking.csv contains the data for the baseline fuzzer, and student_fuzzer_benchmarking.csv contains the data for my fuzzer.

## Usage

To reproduce my experimental results, open a Terminal in the experiments directory and run `python3 experiment.py`. The results will be stored in baseline_fuzzer_benchmarking.csv and student_fuzzer_benchmarking.csv in the same directory.