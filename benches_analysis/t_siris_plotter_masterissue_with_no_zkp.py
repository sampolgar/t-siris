import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import io

# Assuming df already contains all the data including issue_master_no_zkp
csv_data = """scheme,operation,n_participants,threshold,attributes,mean_ms
t_siris,issue_master,4,3,4,16.423840885624998
t_siris,issue_master,4,3,8,25.51271336699999
t_siris,issue_master,4,3,16,45.09694443
t_siris,issue_master,4,3,32,79.746244485
t_siris,issue_master,4,3,64,149.376178725
t_siris,issue_master,4,3,128,288.05480457
t_siris,issue_master,16,9,4,48.540203881666656
t_siris,issue_master,16,9,8,74.8565695925
t_siris,issue_master,16,9,16,130.913721455
t_siris,issue_master,16,9,32,238.08911834
t_siris,issue_master,16,9,64,450.01635788
t_siris,issue_master,16,9,128,873.68781124
t_siris,issue_master,64,33,4,180.67824106
t_siris,issue_master,64,33,8,278.01805501
t_siris,issue_master,64,33,16,483.97570826
t_siris,issue_master,64,33,32,885.19940295
t_siris,issue_master,64,33,64,1641.4431516900001
t_siris,issue_master,64,33,128,3189.3278416900002
t_siris,issue_master_no_zkp,4,3,4,2.3170725820180578
t_siris,issue_master_no_zkp,4,3,8,3.819682933488109
t_siris,issue_master_no_zkp,4,3,16,7.017571324545455
t_siris,issue_master_no_zkp,4,3,32,12.99483177083334
t_siris,issue_master_no_zkp,4,3,64,25.10739089833333
t_siris,issue_master_no_zkp,4,3,128,49.995849055
t_siris,issue_master_no_zkp,16,9,4,6.598695960434782
t_siris,issue_master_no_zkp,16,9,8,11.267185443571432
t_siris,issue_master_no_zkp,16,9,16,20.06328854875
t_siris,issue_master_no_zkp,16,9,32,38.0789441625
t_siris,issue_master_no_zkp,16,9,64,74.64162932000002
t_siris,issue_master_no_zkp,16,9,128,146.496840435
t_siris,issue_master_no_zkp,64,33,4,25.543937998333323
t_siris,issue_master_no_zkp,64,33,8,41.846343145000006
t_siris,issue_master_no_zkp,64,33,16,74.75651896
t_siris,issue_master_no_zkp,64,33,32,141.192019805
t_siris,issue_master_no_zkp,64,33,64,272.54375627999997
t_siris,issue_master_no_zkp,64,33,128,538.8475721"""



df = pd.read_csv(io.StringIO(csv_data))

# Filter for just the operations we want to compare
operations = ['issue_master', 'issue_master_no_zkp']

# More descriptive operation names for the plots
operation_display_names = {
    'issue_master': 'Issue Master (with ZKP verify)',
    'issue_master_no_zkp': 'Issue Master (no ZKP verify)'
}

# More descriptive operation names for the legend
operation_display_names = {
    'issue_master': 'With ZKP Verification',
    'issue_master_no_zkp': 'Without ZKP Verification'
}

# N values to compare
n_values = [4, 16, 64]

# Colors for different N values
n_colors = {
    4: '#E45932',   # Orange-Red
    16: '#4A90E2',  # Blue
    64: '#50C878'   # Green
}

# Line styles for different operations
operation_linestyles = {
    'issue_master': '-',          # Solid
    'issue_master_no_zkp': '--'   # Dashed
}

# Markers for different operations
operation_markers = {
    'issue_master': 'o',        # Circle
    'issue_master_no_zkp': 's'  # Square
}

# Create a single figure
plt.figure(figsize=(10, 6))

# Attribute counts for x-axis
attribute_counts = [4, 8, 16, 32, 64, 128]

# Plot each combination of operation and N value
for operation in operations:
    for n_value in n_values:
        # Get data for this operation and N value
        op_data = df[(df['operation'] == operation) & (df['n_participants'] == n_value)]
        
        # Sort by attribute count
        op_data = op_data.sort_values('attributes')
        
        # Plot data
        plt.plot(op_data['attributes'], op_data['mean_ms'],
                marker=operation_markers[operation],
                color=n_colors[n_value],
                linestyle=operation_linestyles[operation],
                linewidth=2,
                markersize=8,
                label=f'N={n_value}, {operation_display_names[operation]}')

# Set plot title and labels
plt.title('Issue Performance With vs. W/O ZKP Vfy', fontsize=16)
plt.xlabel('Number of Attributes (n)', fontsize=14)
plt.ylabel('Time (ms)', fontsize=14)

# Set x-axis to use attribute counts
plt.xticks(attribute_counts)

# Set y-axis to log scale to better show the differences
# plt.yscale('log')

# Add grid
plt.grid(True, linestyle='--', alpha=0.7)

# Add legend with better placement
plt.legend(fontsize=10, loc='upper left', bbox_to_anchor=(1, 1))

# Adjust layout to make room for the legend
plt.tight_layout(rect=[0, 0, 0.85, 1])

# Save the figure
plt.savefig('issue_master_zkp_comparison_single_plot.png', dpi=300, bbox_inches='tight')

# Display the plot
plt.show()