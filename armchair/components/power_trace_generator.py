#Code adapted from one of ARCHER's infamous jupyter notebooks

import csv
import sys
import re
import pandas as pd
import numpy as np
from tqdm import tqdm
from multiprocessing import Pool, cpu_count
from pathlib import Path


#### Fundamental HW HD functions
def HD(a,b):
    """
    Computes the hamming distance between two integers
    """
    hd = 0
    diff = a^b
    while diff:
        hd += diff & 1
        diff >>= 1
    return hd

def HD_bin(a,b):
#     print(type(sum(c1 != c2 for c1, c2 in zip(a, b)) ))
    return sum(c1 != c2 for c1, c2 in zip(a, b))

def HW(a):
    """
    Computes the hamming weight of an integer
    """
    return sum([a&(1<<i)>0 for i in range(32)])

def binstr(x, size=32):
    return bin(x)[2:].rjust(size, "0")

def extract_number(filename):
    """## helper for create_trace_file

    ### Args:
        - `filename (_type_)`: _description_

    ### Returns:
        - `_type_`: _description_
    """
    match = re.search(r'trace_(\d+)', filename.stem)
    return int(match.group(1)) if match else float('inf')



#### Functions to generate simulated power traces (HD, HW and ID) for all registers
# ********************************************************************************************************************
def create_opt_HW_trace(filename, cols=selected_registers):
    df = pd.read_csv(filename)
    df.fillna('', inplace=True)

    # Convert selected register columns from hex to integer
    reg_int = df[cols].applymap(lambda x: int(x[2:], 16) if x else 0)

    # Compute the Hamming weights
    hw_ref = reg_int.applymap(HW).values
    return np.sum(hw_ref, axis=1)


# ********************************************************************************************************************
def create_opt_HD_trace(filename, cols=selected_registers):
    df = pd.read_csv(filename)
    df.fillna('', inplace=True)
    # reg_int = df[cols].applymap(lambda x: int(x[2:], 16) if x else 0)
    reg_int = df[cols].apply(lambda col: col.map(lambda x: int(x[2:], 16) if x else 0))
    NUM_ROWS, NUM_COLS = reg_int.shape

    reg_int_shifted = reg_int.shift(-1)  # Create a shifted DataFrame
    # reg_int = reg_int.iloc[:-1]
    # reg_int_shifted = reg_int_shifted.iloc[:-1]

    reg_int = reg_int.to_numpy()  # Convert to NumPy arrays for efficient computation
    reg_int_shifted = reg_int_shifted.to_numpy()  # Convert to NumPy arrays for efficient computation
    hd_ref = [sum(HD(int(reg_int[i, j]), int(reg_int_shifted[i, j])) for j in range(NUM_COLS))
              for i in range(NUM_ROWS - 1)
              ]
    return hd_ref


# ********************************************************************************************************************
def create_ID_trace(filename, cols):
    """
    reads an execution trace in csv format
    returns
    - the ID or the sum of  the content of all registers for each instruction
    - the total number of instructions

    """
    df = pd.read_csv(filename)
    df.fillna('', inplace=True)
    reg = df[cols]
    # convert hex register values to binary and decimal values
    reg_dec = []
    for col in cols:
        reg_dec.append(reg[col].apply(lambda x: int(x, 16)))
    number_instructions = len(reg_dec[0])  # number of instructions
    ID_ref = np.zeros((number_instructions, len(cols)))
    for col in range(len(cols)):
        for i in range(number_instructions):
            ID_ref[i, col] = reg_dec[col][i]
    return np.sum(ID_ref, axis=1)

#### Optimized code for computing HD, HW and ID simulated traces for all executions

### creates files in order
def create_trace_file(folder, name_output_file, leakage_model, numberTraces=100, cols=selected_registers):
    """
     creates a npz file from a folder containing csv with execution traces files
     folder: folder containing the csv files with execution traces
     output_file: name of the npz file to be created
     leakage_model: the leakage model to be used to create the traces (ID, HW, HD)
     cols: list of the columns/registers from the dataset to be used to create the traces
    """
    print("Creating simulation traces model....", leakage_model)
    trace_list = []
    count = 0
    files = sorted(Path(folder).glob('*.csv'), key=extract_number)
    for file in tqdm(files):
        if count >= numberTraces:
            break
        # print('Trace ',count)
        # print('file:', file)
        if leakage_model == 'ID':
            trace = create_ID_trace(file, cols)
        elif leakage_model == 'HW':
            trace = create_opt_HW_trace(file, cols)
        elif leakage_model == 'HD':
            trace = create_opt_HD_trace(file, cols)
        trace_list.append(trace)
        count += 1
    vectors_array = np.array(trace_list)
    np.savez_compressed(name_output_file, vectors_array)

    print("Finished creating the file")


def process_csv_file(file, cols, leakage_model):
    """
    Process a single CSV file based on the specified leakage model and columns.
    """
    #     print('Processing file:', file)
    if leakage_model == 'ID':
        trace = create_ID_trace(file, cols)
    elif leakage_model == 'HW':
        trace = create_opt_HW_trace(file, cols)
    elif leakage_model == 'HD':
        trace = create_opt_HD_trace(file, cols)
    return trace


### code that uses multiprocessing package
def create_npz_file(name_npy_file, folder, leakage_model, cols, num_cores=None):
    """
    Creates a numpy file from a folder containing csv files.

    name_npy_file: name of the numpy file to be created
    folder: folder containing the csv files
    leakage_model: the leakage model to be used to create the traces (ID, HW, HD)
    cols: list of the columns/registers from the dataset to be used to create the traces
    num_cores: number of CPU cores to use in multiprocessing (default is None, which uses all available cores)
    """
    print("Creating simulation traces model....", leakage_model)
    trace_list = []
    count = 0
    # files = list(Path(folder).glob('*.csv'))
    files = sorted(Path(folder).glob('*.csv'), key=extract_number)

    # Determine number of cores to use
    if num_cores is None:
        num_cores = cpu_count()

    # Define a multiprocessing pool with specified number of cores
    with Pool(processes=num_cores) as pool:
        # Process each CSV file in parallel
        results = pool.starmap(process_csv_file, [(file, cols, leakage_model) for file in files])

    trace_list.extend(results)

    vectors_array = np.array(trace_list)
    np.savez_compressed(name_npy_file, vectors_array)
    print("Finished creating the file")

# Example usage:
# create_npz_file("output.npz", "data_folder", "ID", ["col1", "col2"], num_cores=4)  # Use 4 cores

#********************************************************************************************************************
    #TRACE MANIPULATION FUNCTIONS
#********************************************************************************************************************
def load_trace_file(trace_filename):
    """
    Load a trace file and return the trace data.
    """
    data = np.load(trace_filename)
    trace_set=data[data.files[0]]
    number_samples=len(trace_set[0])
    number_traces=len(trace_set)
    print("Load successful!")
    print("Number of traces: ", number_traces)
    print("Number of samples: ", number_samples)
    return trace_set, number_traces, number_samples

load_trace_file('Traces/simulated_HD/fixed_1_Os.npz')
load_trace_file('Traces/simulated_HW/fixed_1_Os.npz')
load_trace_file('Traces/simulated_ID/fixed_1_Os.npz')

#### Functions to compute simulated traces for selected registers
#** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** **

# LM for destination registers
# ********************************************************************************************************************
def create_list_modified_registers(df):
    """
    df : dataframe containing the full reference trace
    return: list of registers that are modified by each instruction
    """
    operands = df['Operands'].to_list()
    types = df['Type'].to_list()
    dest = ['zero']

    for op, typ in zip(operands, types):
        if typ in ['STORE', 'UBRANCH']:
            dest.append('zero')
        else:
            if isinstance(op, str):
                dest.append(op.split(',')[0])
            else:
                dest.append('zero')

    dest.pop()  # remove the last element
    return dest


def select_value(row, col_name='Dest'):
    """
    col_name='Dest' contains a list of columns,
    select the cell which corresponds to the value, column pointed by  the respective value in 'Dest'
    """
    return row[row['Dest']]


def HW_dest(filename, dest_register):
    df = pd.read_csv(filename)
    df.fillna('', inplace=True)

    df['Dest'] = dest_register
    df['Selected_Value'] = df.apply(select_value, axis=1)
    df['HW'] = df['Selected_Value'].apply(lambda x: HW(int(x[2:], 16)))
    hw_trace = df['HW'].to_list()
    return hw_trace


def ID_dest(filename, dest_register):
    df = pd.read_csv(filename)
    df.fillna('', inplace=True)

    df['Dest'] = dest_register
    df['Selected_Value'] = df.apply(select_value, axis=1)
    # df['HW'] = df['Selected_Value'].apply(lambda x: HW(int(x[2:], 16)))
    ID_trace = df['Selected_Value'].to_list()
    int_list = [int(hex_str, 16) for hex_str in ID_trace]
    return int_list


def create_trace_file_dest(folder, name_output_file, leakage_model, list_dest_registers, numberTraces=100, ):
    """
     creates a npz file from a folder containing csv with execution traces files
     folder: folder containing the csv files with execution traces
     output_file: name of the npz file to be created
     leakage_model: the leakage model to be used to create the traces (ID, HW, HD)
     cols: list of the columns/registers from the dataset to be used to create the traces
    """
    print("Creating simulation traces model....", leakage_model)
    trace_list = []
    count = 0
    files = sorted(Path(folder).glob('*.csv'), key=extract_number)
    for file in tqdm(files):
        if count >= numberTraces:
            break
        if leakage_model == 'IDD':
            trace = ID_dest(file, list_dest_registers)
        elif leakage_model == 'HWD':
            trace = HW_dest(file, list_dest_registers)

        trace_list.append(trace)
        count += 1
    vectors_array = np.array(trace_list)
    np.savez_compressed(name_output_file, vectors_array)
    print("Finished creating the file")

selected_registers = ['zero', 'ra', 'sp', 'gp', 'tp', 't0', 't1','t2',
                      's0', 's1', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5',
                      'a6', 'a7', 's2','s3', 's4', 's5', 's6', 's7',
                      's8', 's9', 's10', 's11', 't3', 't4','t5', 't6']

####################### main code #######################

opt_level = 'Os'
modified_byte = '5'
numberTraces = 500

for lm in ['HW','ID','HD']:
    in_folder_name = 'fixed_1_' + opt_level
    in_folder = 'Traces/execution_traces/' + in_folder_name + '/'
    out_filename='Traces/simulated_'+ lm +'/' + in_folder_name + '.npz'
#     create_trace_file(in_folder, out_filename, lm, numberTraces, selected_registers)
    create_npz_file(out_filename, in_folder, lm, selected_registers)


for lm in ['HW','ID','HD']:
    in_folder_name = 'fixed_1_' + opt_level + '_byte_' + modified_byte
    in_folder = 'Traces/execution_traces/' + in_folder_name + '/'
    out_filename='Traces/simulated_'+ lm +'/' + in_folder_name + '.npz'
#     create_trace_file(in_folder, out_filename, lm, numberTraces, selected_registers)
    create_npz_file(out_filename, in_folder, lm, selected_registers)

# lm = 'HW'
for lm in ['HD', 'HW', 'ID']:
    in_folder_name = 'fixed_Os'
    in_folder = 'Traces/execution_traces/' + in_folder_name + '/'
    out_filename='Traces/simulated_'+ lm +'/' + in_folder_name + '.npz'
    create_npz_file(out_filename, in_folder, lm, selected_registers)

    in_folder_name = 'fixed_Os_byte_5'
    in_folder = 'Traces/execution_traces/' + in_folder_name + '/'
    out_filename='Traces/simulated_'+ lm +'/' + in_folder_name + '.npz'
    create_npz_file(out_filename, in_folder, lm, selected_registers)

    in_folder_name = 'fixed_Os_byte_9'
    in_folder = 'Traces/execution_traces/' + in_folder_name + '/'
    out_filename='Traces/simulated_'+ lm +'/' + in_folder_name + '.npz'
    create_npz_file(out_filename, in_folder, lm, selected_registers)


#New fixed dataset
lm = 'HW'
in_folder_name = 'fixed_1_Os'
in_folder = 'Traces/execution_traces/' + in_folder_name + '/'
out_filename='Traces/simulated_'+ lm +'/' + in_folder_name + '.npz'
create_npy_file(out_filename, in_folder, lm, selected_registers)

in_folder_name = 'fixed_1_Os_byte_5'
in_folder = 'Traces/execution_traces/' + in_folder_name + '/'
out_filename='Traces/simulated_'+ lm +'/' + in_folder_name + '.npz'
create_npy_file(out_filename, in_folder, lm, selected_registers)

