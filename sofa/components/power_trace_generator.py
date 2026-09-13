# This file contains some code adapted from one of ARCHER's Jupyter notebooks.

from pathlib import Path

import holoviews as hv
import numpy as np
from bokeh.plotting import show
from holoviews import opts

from sofa.utils.helpers import create_npz_file, create_npy_file
from sofa.utils.register_access import REGISTER_NAMES


def generate_power_traces(
    input_dir: str | Path,
    output_file: str | Path,
    leakage_model: str,
    selected_registers: list[str] | tuple[str, ...] = REGISTER_NAMES,
    format: str = "npz",
    register_model: str = "accessed",
) -> None:
    """
    Generate power traces from the CSV execution traces in the given input directory and save them to the specified output file.
    Args:
        input_dir: the directory containing the execution traces in CSV format.
        output_file: name (and optionally path) of the NPZ file that will be created to store the power traces.
        leakage_model: one of the supported leakage models. Currently, can be 'HD', 'HW', or 'ID'.
        selected_registers: the registers to consider when simulating the power consumption. Default is the following ARM registers: r0,r1,r2,r3,r4,r5,r6,r7,r8,r9,r10,r11,r12,sp,lr,pc.
        format: the format in which to save the power traces. Can be 'npz' (default) or 'npy'.
        register_model: use only instruction-accessed registers (default), or all selected registers.

    Returns:
        None. The function saves the generated power traces to the specified output file in NPZ format.
    """

    if format == 'npz':
        create_npz_file(
            output_file,
            input_dir,
            leakage_model,
            selected_registers,
            register_model=register_model,
        )
    else:
        create_npy_file(
            output_file,
            input_dir,
            leakage_model,
            selected_registers,
            register_model=register_model,
        )


def show_power_traces(
    input_file: str | Path,
    leakage_model: str,
    start: int = 0,
    end: int | None = None,
    format: str = "npz",
    register_model: str = "accessed",
) -> None:
    """
    Display power traces from the specified input file using Holoviews.

    Args:
        input_file: the NPZ or NPY file containing the power traces.
        leakage_model: one of the supported leakage models. Currently, can be 'HD', 'HW', or 'ID'.
        start: the starting index of the traces to display (default is 0).
        end: the ending index of the traces to display (default is None, which means all traces).
        format: the format of the input file, either 'npz' or 'npy'.
        register_model: register selection model used to generate the trace.

    Returns:
        None
    """

    # Load traces

    if format == "npz":
        with np.load(input_file) as archive:
            traces = archive["arr_0"]
    else:
        traces = np.load(input_file)



    hv.extension('bokeh')
    # Loop through each trace and add it to the plot
    plot_list=[]
    for i, trace in enumerate(traces):
        # Create a curve for each trace
        curve = hv.Curve(trace, label=f'Trace {start + i}')

        plot_list.append(curve)
        
    match leakage_model:
        case 'ID':
            plot = hv.Overlay(plot_list).opts(opts.Curve(width=800), 
            opts.Overlay(
                xlabel='Time samples', 
                ylabel='Power consumption',
                legend_position='right',
                title=f'Power consumption under ID/{register_model} model'
            ))
        
        case 'HD':
            plot=hv.Overlay(plot_list).opts(opts.Curve(width=800),
                                            opts.Overlay(
                                                xlabel='Instruction',
                                                ylabel='Power consumption',
                                                legend_position='right',
                                                title=f'Power consumption under HD/{register_model} model'
                                            ))

        case 'HW':
            plot=hv.Overlay(plot_list).opts(opts.Curve(width=800),
                                            opts.Overlay(
                                                xlabel='Instruction',
                                                ylabel='Power consumption',
                                                legend_position='right',
                                                title=f'Power consumption under HW/{register_model} model'
                                            )
            )

        case _ :
            plot = hv.Overlay(plot_list).opts(opts.Curve(width=800))


    show(hv.render(plot))
    print("Power traces are displayed inside your browser.")

