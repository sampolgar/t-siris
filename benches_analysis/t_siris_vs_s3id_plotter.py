import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import io

# Combine all the data
data_str = """scheme,operation,n_participants,threshold,attributes,mean_ms
t_siris,aggregate,4,3,4,23.90208711455959
t_siris,aggregate,4,3,8,35.44437404794787
t_siris,aggregate,4,3,16,56.35653982320198
t_siris,aggregate,4,3,32,98.55855535376645
t_siris,aggregate,4,3,64,181.97207883185066
t_siris,aggregate,4,3,128,341.15892724034326
t_siris,aggregate,16,9,4,56.30261923562104
t_siris,aggregate,16,9,8,85.20480364842342
t_siris,aggregate,16,9,16,143.20225341076746
t_siris,aggregate,16,9,32,268.4607354055472
t_siris,aggregate,16,9,64,481.7180912078235
t_siris,aggregate,16,9,128,962.7982225470697
t_siris,aggregate,64,33,4,189.15598657848618
t_siris,aggregate,64,33,8,329.7958776966816
t_siris,aggregate,64,33,16,535.3831151921261
t_siris,aggregate,64,33,32,923.8487778080734
t_siris,aggregate,64,33,64,1845.1932589718254
t_siris,aggregate,64,33,128,3378.4380017894197

t_siris,aggregate_no_zkp,4,3,4,10.046955071899223
t_siris,aggregate_no_zkp,4,3,8,13.675703514555305
t_siris,aggregate_no_zkp,4,3,16,19.576845163185077
t_siris,aggregate_no_zkp,4,3,32,31.866506756266453
t_siris,aggregate_no_zkp,4,3,64,56.64482477685066
t_siris,aggregate_no_zkp,4,3,128,105.02365191234325
t_siris,aggregate_no_zkp,16,9,4,14.684630434505584
t_siris,aggregate_no_zkp,16,9,8,21.010032786581313
t_siris,aggregate_no_zkp,16,9,16,35.196185874403824
t_siris,aggregate_no_zkp,16,9,32,59.3279600555472
t_siris,aggregate_no_zkp,16,9,64,110.79092631032351
t_siris,aggregate_no_zkp,16,9,128,212.1299591570697
t_siris,aggregate_no_zkp,64,33,4,38.6208796295973
t_siris,aggregate_no_zkp,64,33,8,60.23678052868158
t_siris,aggregate_no_zkp,64,33,16,98.73888988212613
t_siris,aggregate_no_zkp,64,33,32,165.7375707230734
t_siris,aggregate_no_zkp,64,33,64,312.4050797918255
t_siris,aggregate_no_zkp,64,33,128,614.6494317694196"""

s3id_data_str = """scheme,operation,N,n,t,t',l,L,mean_ms
s3id,dedup,4,4,3,3,,16,36.934316880000004
s3id,dedup,4,8,3,5,,16,72.05472953
s3id,dedup,4,16,3,9,,16,158.51620337
s3id,dedup,4,32,3,17,,16,506.34491251
s3id,dedup,4,64,3,33,,16,1713.79025708
s3id,dedup,4,128,3,65,,16,6441.52452707
s3id,dedup,16,4,9,3,,16,47.082429335
s3id,dedup,16,8,9,5,,16,86.95541836
s3id,dedup,16,16,9,9,,16,202.5217054
s3id,dedup,16,32,9,17,,16,569.98663917
s3id,dedup,16,64,9,33,,16,1864.09891121
s3id,dedup,16,128,9,65,,16,6689.433138390001
s3id,dedup,64,4,33,3,,16,83.62920834
s3id,dedup,64,8,33,5,,16,177.22878581999998
s3id,dedup,64,16,33,9,,16,771.0991766000001
s3id,dedup,64,32,33,17,,16,934.21792165
s3id,dedup,64,64,33,33,,16,2604.7979811799996
s3id,dedup,64,128,33,65,,16,8529.13585965"""

# Load data into DataFrames
df1 = pd.read_csv(io.StringIO(data_str))
df2 = pd.read_csv(io.StringIO(s3id_data_str))

# Rename columns in df2 to match df1
df2 = df2.rename(columns={'N': 'n_participants', 'n': 'attributes', 't': 'threshold'})

# Combine dataframes
df = pd.concat([df1, df2])


# Define operations to compare
operations_left = ['aggregate', 'dedup']  # T-SIRIS with ZKP vs S3ID
operations_right = ['aggregate_no_zkp', 'dedup']  # T-SIRIS without ZKP vs S3ID

# Display names for operations
operation_display_names = {
    'aggregate': 'T-SIRIS (with ZKP)',
    'aggregate_no_zkp': 'T-SIRIS (without ZKP)',
    'dedup': 'S3ID'
}

# N values to compare
n_values = [4, 16, 64]

# Colors as requested
operation_colors = {
    'aggregate': '#50C878',      # Green for T-SIRIS
    'aggregate_no_zkp': '#50C878', # Green for T-SIRIS
    'dedup': '#E45932'           # Orange for S3ID
}

# Line styles for different N values
n_linestyles = {
    4: '-',   # Solid
    16: '--', # Dashed
    64: ':'   # Dotted
}

# Markers for different N values
n_markers = {
    4: 'o',   # Circle
    16: 's',  # Square
    64: '^'   # Triangle
}

# Create a figure with two subplots side by side
fig, axes = plt.subplots(1, 2, figsize=(18, 8))

# Attribute counts for x-axis
attribute_counts = [4, 8, 16, 32, 64, 128]

# For each subplot (left and right)
for i, (ax, operations) in enumerate(zip(axes, [operations_left, operations_right])):
    # Plot each combination of operation and N value
    for operation in operations:
        for n_value in n_values:
            # Get data for this operation and N value
            if operation in ['aggregate', 'aggregate_no_zkp']:
                op_data = df[(df['scheme'] == 't_siris') & 
                             (df['operation'] == operation) & 
                             (df['n_participants'] == n_value)]
            else:  # 'dedup'
                op_data = df[(df['scheme'] == 's3id') & 
                             (df['operation'] == operation) & 
                             (df['n_participants'] == n_value)]
            
            # Sort by attribute count
            op_data = op_data.sort_values('attributes')
            
            # Plot data
            ax.plot(op_data['attributes'], op_data['mean_ms'],
                    # marker=n_markers[n_value],
                    color=operation_colors[operation],
                    linestyle=n_linestyles[n_value],
                    linewidth=2,
                    markersize=8,
                    label=f'{operation_display_names[operation]}, N={n_value}')

    # Set subplot title
    if i == 0:
        ax.set_title('T-SIRIS (with ZKP) vs S3ID', fontsize=16)
    else:
        ax.set_title('T-SIRIS (without ZKP, a closer analysis) vs S3ID', fontsize=16)
    
    # Set labels
    ax.set_xlabel('Number of Attributes (n)', fontsize=14)
    ax.set_ylabel('Time (ms)', fontsize=14)
    
    # Set x-axis to use attribute counts
    ax.set_xticks(attribute_counts)
    ax.set_xticklabels(attribute_counts)
    
    # Set y-axis to log scale
    # ax.set_yscale('log')
    
    # Add grid
    ax.grid(True, linestyle='--', alpha=0.7)
    
    # Add legend
    ax.legend(fontsize=10)

# Set a common title for the entire figure
fig.suptitle('Performance Comparison: Our Construction T-SIRIS vs S3ID', fontsize=18)

# Adjust layout
plt.tight_layout(rect=[0, 0, 1, 0.95])  # Make room for the suptitle

# Save the figure
plt.savefig('tsiris_vs_s3id_comparison_side_by_side.png', dpi=300, bbox_inches='tight')

# Display the plot
plt.show()


# # Define operations to compare and display names
# operations = {
#     'aggregate': 'T-SIRIS (with ZKP)',
#     'aggregate_no_zkp': 'T-SIRIS (no ZKP)',
#     'dedup': 'S3ID'
# }

# # Define N values to compare
# n_values = [4, 16, 64]

# # Colors for different operations
# operation_colors = {
#     'aggregate': '#50C878',      # Orange-Red
#     'aggregate_no_zkp': '#4A90E2', # Blue
#     'dedup': '#E45932'           # Green
# }

# # Line styles for different N values
# n_linestyles = {
#     4: '-',   # Solid
#     16: '--', # Dashed
#     64: ':'   # Dotted
# }

# # Markers for different N values
# n_markers = {
#     4: 'o',   # Circle
#     16: 's',  # Square
#     64: '^'   # Triangle
# }

# # Create a figure
# plt.figure(figsize=(14, 8))

# # Attribute counts for x-axis
# attribute_counts = [4, 8, 16, 32, 64, 128]

# # Plot each combination of operation and N value
# for operation, display_name in operations.items():
#     for n_value in n_values:
#         # Get data for this operation and N value
#         if operation in ['aggregate', 'aggregate_no_zkp']:
#             op_data = df[(df['scheme'] == 't_siris') & 
#                          (df['operation'] == operation) & 
#                          (df['n_participants'] == n_value)]
#         else:  # 'dedup'
#             op_data = df[(df['scheme'] == 's3id') & 
#                          (df['operation'] == operation) & 
#                          (df['n_participants'] == n_value)]
        
#         # Sort by attribute count
#         op_data = op_data.sort_values('attributes')
        
#         # Plot data
#         plt.plot(op_data['attributes'], op_data['mean_ms'],
#                 # marker=n_markers[n_value],
#                 color=operation_colors[operation],
#                 linestyle=n_linestyles[n_value],
#                 linewidth=2,
#                 markersize=10,
#                 label=f'{display_name}, N={n_value}')

# # Set plot title and labels
# # plt.title('Perf. Eval: T-SIRIS(Obtain, IssueContext + Sybil, Show, Verify) vs S3ID (Dedup)', fontsize=16)
# plt.title('Comparing Our Construction T-SIRIS with S3ID', fontsize=16)
# plt.xlabel('Number of Attributes (n)', fontsize=16)
# plt.ylabel('Time (ms)', fontsize=16)

# # Set x-axis to use attribute counts
# plt.xticks(attribute_counts)

# # Set y-axis to log scale to better show the differences
# # plt.yscale('log')

# # Add grid
# plt.grid(True, linestyle='--', alpha=0.7)

# # Add legend with better placement
# plt.legend(fontsize=12, bbox_to_anchor=(1.05, 1), loc='upper left')

# # Adjust layout to make room for the legend
# plt.tight_layout(rect=[0, 0, 0.82, 1])

# # Save the figure
# plt.savefig('tsiris_vs_s3id_comparison.png', dpi=300, bbox_inches='tight')

# # Display the plot
# plt.show()






























# csv_data = """scheme,operation,n_participants,threshold,attributes,mean_ms
# t_siris,obtain_master,4,3,4,2.6396777237073468
# t_siris,obtain_master,4,3,8,4.336612887448239
# t_siris,obtain_master,4,3,16,7.301413987490351
# t_siris,obtain_master,4,3,32,13.168383933888888
# t_siris,obtain_master,4,3,64,24.92002284454546
# t_siris,obtain_master,4,3,128,47.27598903
# t_siris,obtain_master,16,9,4,2.719964629492972
# t_siris,obtain_master,16,9,8,4.434522406343196
# t_siris,obtain_master,16,9,16,7.356277081915867
# t_siris,obtain_master,16,9,32,13.231807546111108
# t_siris,obtain_master,16,9,64,24.764775942727272
# t_siris,obtain_master,16,9,128,47.31681417666667
# t_siris,obtain_master,64,33,4,4.706494009747906
# t_siris,obtain_master,64,33,8,6.361218124556387
# t_siris,obtain_master,64,33,16,9.335534103076924
# t_siris,obtain_master,64,33,32,15.551623283529418
# t_siris,obtain_master,64,33,64,27.166754630000007
# t_siris,obtain_master,64,33,128,58.058908657999986
# t_siris,issue_context_no_zkp,4,3,4,4.507865306625343
# t_siris,issue_context_no_zkp,4,3,8,6.410782658829657
# t_siris,issue_context_no_zkp,4,3,16,9.285364991649738
# t_siris,issue_context_no_zkp,4,3,32,15.530462655
# t_siris,issue_context_no_zkp,4,3,64,28.40703365
# t_siris,issue_context_no_zkp,4,3,128,54.08050924199999
# t_siris,issue_context_no_zkp,16,9,4,8.870440997216882
# t_siris,issue_context_no_zkp,16,9,8,13.665275483157897
# t_siris,issue_context_no_zkp,16,9,16,24.85183098363637
# t_siris,issue_context_no_zkp,16,9,32,42.94018195
# t_siris,issue_context_no_zkp,16,9,64,82.5492846825
# t_siris,issue_context_no_zkp,16,9,128,160.83401874
# t_siris,issue_context_no_zkp,64,33,4,30.95807514111112
# t_siris,issue_context_no_zkp,64,33,8,50.88314074199999
# t_siris,issue_context_no_zkp,64,33,16,86.41014472
# t_siris,issue_context_no_zkp,64,33,32,147.026260845
# t_siris,issue_context_no_zkp,64,33,64,281.89459622000004
# t_siris,issue_context_no_zkp,64,33,128,552.92006501
# t_siris,show,4,3,4,1.1941485631094013
# t_siris,show,4,3,8,1.2689889495022122
# t_siris,show,4,3,16,1.314793120436966
# t_siris,show,4,3,32,1.4923686215746677
# t_siris,show,4,3,64,1.6439200500844375
# t_siris,show,4,3,128,1.9863364618294543
# t_siris,show,16,9,4,1.2370163139065165
# t_siris,show,16,9,8,1.2485880611611777
# t_siris,show,16,9,16,1.32090345514077
# t_siris,show,16,9,32,1.4939939683924741
# t_siris,show,16,9,64,1.8045757417723778
# t_siris,show,16,9,128,2.3017653697017115
# t_siris,show,64,33,4,1.2488694231872508
# t_siris,show,64,33,8,1.3200015561617753
# t_siris,show,64,33,16,1.3309588449791512
# t_siris,show,64,33,32,1.4970602095830758
# t_siris,show,64,33,64,1.6785231644036007
# t_siris,show,64,33,128,2.007555989081418
# t_siris,verify,4,3,4,1.7052634784571312
# t_siris,verify,4,3,8,1.6593190187751976
# t_siris,verify,4,3,16,1.6752730636080229
# t_siris,verify,4,3,32,1.6752915458028965
# t_siris,verify,4,3,64,1.6738482322207637
# t_siris,verify,4,3,128,1.6808171785138097
# t_siris,verify,16,9,4,1.8572084938892124
# t_siris,verify,16,9,8,1.661646835919043
# t_siris,verify,16,9,16,1.6671743537108181
# t_siris,verify,16,9,32,1.661976591043617
# t_siris,verify,16,9,64,1.6722899433238658
# t_siris,verify,16,9,128,1.6773608707013155
# t_siris,verify,64,33,4,1.7074410555510195
# t_siris,verify,64,33,8,1.6724201059634247
# t_siris,verify,64,33,16,1.6622522140700513
# t_siris,verify,64,33,32,1.6626263849609164
# t_siris,verify,64,33,64,1.6652057774218214
# t_siris,verify,64,33,128,1.6629021123382524"""


# def aggregate_operations(df: pd.DataFrame) -> pd.DataFrame:
#     """
#     Given a DataFrame `df` with columns:
#       - scheme
#       - operation
#       - n_participants
#       - threshold
#       - attributes
#       - mean_ms
#     this function appends rows where operation == 'aggregate', summing mean_ms
#     across all operations for each unique combination of scheme, n_participants,
#     threshold, and attributes.
#     """
#     # define the grouping keys
#     group_keys = ['scheme', 'n_participants', 'threshold', 'attributes']
    
#     # compute the sum of mean_ms for each group
#     agg_df = (
#         df
#         .groupby(group_keys, as_index=False)['mean_ms']
#         .sum()
#         .assign(operation='aggregate')
#         .loc[:, df.columns]  # reorder to match original columns
#     )
    
#     # append the aggregate rows
#     result = pd.concat([df, agg_df], ignore_index=True)
#     return result

# df = pd.read_csv(io.StringIO(csv_data))
# augmented_df = aggregate_operations(df)
# augmented_df.to_csv('aggregated_output.csv', index=False)


# scheme,operation,n_participants,threshold,attributes,mean_ms
# t_siris,aggregate,4,3,4,23.90208711455959
# t_siris,aggregate,4,3,8,35.44437404794787
# t_siris,aggregate,4,3,16,56.35653982320198
# t_siris,aggregate,4,3,32,98.55855535376645
# t_siris,aggregate,4,3,64,181.97207883185066
# t_siris,aggregate,4,3,128,341.15892724034326
# t_siris,aggregate,16,9,4,56.30261923562104
# t_siris,aggregate,16,9,8,85.20480364842342
# t_siris,aggregate,16,9,16,143.20225341076746
# t_siris,aggregate,16,9,32,268.4607354055472
# t_siris,aggregate,16,9,64,481.7180912078235
# t_siris,aggregate,16,9,128,962.7982225470697
# t_siris,aggregate,64,33,4,189.15598657848618
# t_siris,aggregate,64,33,8,329.7958776966816
# t_siris,aggregate,64,33,16,535.3831151921261
# t_siris,aggregate,64,33,32,923.8487778080734
# t_siris,aggregate,64,33,64,1845.1932589718254
# t_siris,aggregate,64,33,128,3378.4380017894197

# scheme,operation,n_participants,threshold,attributes,mean_ms
# t_siris,aggregate_no_zkp,4,3,4,10.046955071899223
# t_siris,aggregate_no_zkp,4,3,8,13.675703514555305
# t_siris,aggregate_no_zkp,4,3,16,19.576845163185077
# t_siris,aggregate_no_zkp,4,3,32,31.866506756266453
# t_siris,aggregate_no_zkp,4,3,64,56.64482477685066
# t_siris,aggregate_no_zkp,4,3,128,105.02365191234325
# t_siris,aggregate_no_zkp,16,9,4,14.684630434505584
# t_siris,aggregate_no_zkp,16,9,8,21.010032786581313
# t_siris,aggregate_no_zkp,16,9,16,35.196185874403824
# t_siris,aggregate_no_zkp,16,9,32,59.3279600555472
# t_siris,aggregate_no_zkp,16,9,64,110.79092631032351
# t_siris,aggregate_no_zkp,16,9,128,212.1299591570697
# t_siris,aggregate_no_zkp,64,33,4,38.6208796295973
# t_siris,aggregate_no_zkp,64,33,8,60.23678052868158
# t_siris,aggregate_no_zkp,64,33,16,98.73888988212613
# t_siris,aggregate_no_zkp,64,33,32,165.7375707230734
# t_siris,aggregate_no_zkp,64,33,64,312.4050797918255
# t_siris,aggregate_no_zkp,64,33,128,614.6494317694196



# scheme,operation,N,n,t,t',l,L,mean_ms
# s3id,dedup,4,4,3,3,,16,36.934316880000004
# s3id,dedup,4,8,3,5,,16,72.05472953
# s3id,dedup,4,16,3,9,,16,158.51620337
# s3id,dedup,4,32,3,17,,16,506.34491251
# s3id,dedup,4,64,3,33,,16,1713.79025708
# s3id,dedup,4,128,3,65,,16,6441.52452707
# s3id,dedup,16,4,9,3,,16,47.082429335
# s3id,dedup,16,8,9,5,,16,86.95541836
# s3id,dedup,16,16,9,9,,16,202.5217054
# s3id,dedup,16,32,9,17,,16,569.98663917
# s3id,dedup,16,64,9,33,,16,1864.09891121
# s3id,dedup,16,128,9,65,,16,6689.433138390001
# s3id,dedup,64,4,33,3,,16,83.62920834
# s3id,dedup,64,8,33,5,,16,177.22878581999998
# s3id,dedup,64,16,33,9,,16,771.0991766000001
# s3id,dedup,64,32,33,17,,16,934.21792165
# s3id,dedup,64,64,33,33,,16,2604.7979811799996
# s3id,dedup,64,128,33,65,,16,8529.13585965