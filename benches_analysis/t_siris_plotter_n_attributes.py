import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import io

# Load the CSV data
csv_data = """scheme,operation,n_participants,threshold,attributes,mean_ms
t_siris,obtain_master,4,3,4,2.6396777237073468
t_siris,obtain_master,4,3,8,4.336612887448239
t_siris,obtain_master,4,3,16,7.301413987490351
t_siris,obtain_master,4,3,32,13.168383933888888
t_siris,obtain_master,4,3,64,24.92002284454546
t_siris,obtain_master,4,3,128,47.27598903
t_siris,obtain_master,16,9,4,2.719964629492972
t_siris,obtain_master,16,9,8,4.434522406343196
t_siris,obtain_master,16,9,16,7.356277081915867
t_siris,obtain_master,16,9,32,13.231807546111108
t_siris,obtain_master,16,9,64,24.764775942727272
t_siris,obtain_master,16,9,128,47.31681417666667
t_siris,obtain_master,64,33,4,4.706494009747906
t_siris,obtain_master,64,33,8,6.361218124556387
t_siris,obtain_master,64,33,16,9.335534103076924
t_siris,obtain_master,64,33,32,15.551623283529418
t_siris,obtain_master,64,33,64,27.166754630000007
t_siris,obtain_master,64,33,128,58.058908657999986
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
t_siris,obtain_context,4,3,4,4.096348262435877
t_siris,obtain_context,4,3,8,5.737150363666908
t_siris,obtain_context,4,3,16,8.53946037704629
t_siris,obtain_context,4,3,32,14.759002912941174
t_siris,obtain_context,4,3,64,26.424232542000002
t_siris,obtain_context,4,3,128,53.15578994166667
t_siris,obtain_context,16,9,4,3.9798543233339
t_siris,obtain_context,16,9,8,5.716265944830601
t_siris,obtain_context,16,9,16,8.868190952016148
t_siris,obtain_context,16,9,32,14.920711610666675
t_siris,obtain_context,16,9,64,27.961082870000006
t_siris,obtain_context,16,9,128,49.42410691599999
t_siris,obtain_context,64,33,4,4.028109731493967
t_siris,obtain_context,64,33,8,5.726700191184108
t_siris,obtain_context,64,33,16,8.772724565691364
t_siris,obtain_context,64,33,32,15.064052130588234
t_siris,obtain_context,64,33,64,27.014008420000003
t_siris,obtain_context,64,33,128,50.372380994000004
t_siris,issue_context,4,3,4,18.362997349285713
t_siris,issue_context,4,3,8,28.17945319222222
t_siris,issue_context,4,3,16,46.06505965166665
t_siris,issue_context,4,3,32,82.2225112525
t_siris,issue_context,4,3,64,153.734287705
t_siris,issue_context,4,3,128,290.21578457
t_siris,issue_context,16,9,4,50.48842979833334
t_siris,issue_context,16,9,8,77.860046345
t_siris,issue_context,16,9,16,132.85789852
t_siris,issue_context,16,9,32,252.0729573
t_siris,issue_context,16,9,64,453.47644958
t_siris,issue_context,16,9,128,911.50228213
t_siris,issue_context,64,33,4,181.49318209
t_siris,issue_context,64,33,8,320.44223791
t_siris,issue_context,64,33,16,523.05437003
t_siris,issue_context,64,33,32,905.13746793
t_siris,issue_context,64,33,64,1814.68277543
t_siris,issue_context,64,33,128,3316.70863503
t_siris,show,4,3,4,1.1941485631094013
t_siris,show,4,3,8,1.2689889495022122
t_siris,show,4,3,16,1.314793120436966
t_siris,show,4,3,32,1.4923686215746677
t_siris,show,4,3,64,1.6439200500844375
t_siris,show,4,3,128,1.9863364618294543
t_siris,show,16,9,4,1.2370163139065165
t_siris,show,16,9,8,1.2485880611611777
t_siris,show,16,9,16,1.32090345514077
t_siris,show,16,9,32,1.4939939683924741
t_siris,show,16,9,64,1.8045757417723778
t_siris,show,16,9,128,2.3017653697017115
t_siris,show,64,33,4,1.2488694231872508
t_siris,show,64,33,8,1.3200015561617753
t_siris,show,64,33,16,1.3309588449791512
t_siris,show,64,33,32,1.4970602095830758
t_siris,show,64,33,64,1.6785231644036007
t_siris,show,64,33,128,2.007555989081418
t_siris,verify,4,3,4,1.7052634784571312
t_siris,verify,4,3,8,1.6593190187751976
t_siris,verify,4,3,16,1.6752730636080229
t_siris,verify,4,3,32,1.6752915458028965
t_siris,verify,4,3,64,1.6738482322207637
t_siris,verify,4,3,128,1.6808171785138097
t_siris,verify,16,9,4,1.8572084938892124
t_siris,verify,16,9,8,1.661646835919043
t_siris,verify,16,9,16,1.6671743537108181
t_siris,verify,16,9,32,1.661976591043617
t_siris,verify,16,9,64,1.6722899433238658
t_siris,verify,16,9,128,1.6773608707013155
t_siris,verify,64,33,4,1.7074410555510195
t_siris,verify,64,33,8,1.6724201059634247
t_siris,verify,64,33,16,1.6622522140700513
t_siris,verify,64,33,32,1.6626263849609164
t_siris,verify,64,33,64,1.6652057774218214
t_siris,verify,64,33,128,1.6629021123382524"""

df = pd.read_csv(io.StringIO(csv_data))

# Filter for n_participants = 16
df_n16 = df[df['n_participants'] == 16]

# List of operations to plot
operations = ['obtain_master', 'issue_master', 'obtain_context', 'issue_context', 'show', 'verify']

# More descriptive operation names for the plots
operation_display_names = {
    'obtain_master': 'Obtain Master',
    'issue_master': 'Issue Master',
    'obtain_context': 'Obtain Context',
    'issue_context': 'Issue Context',
    'show': 'Show',
    'verify': 'Verify'
}


 



# # Colors for the plots
# colors = {
#     'obtain_master': '#E45932',  # Orange-Red
#     'issue_master': '#4A90E2',   # Blue
#     'obtain_context': '#50C878', # Green
#     'issue_context': '#9370DB',  # Purple
#     'show': '#FFD700',           # Gold
#     'verify': '#FF6347'          # Tomato
# }

# # Attribute counts for x-axis
# attribute_counts = [4, 8, 16, 32, 64, 128]

# # Create a figure with 2x3 subplots
# fig, axes = plt.subplots(2, 3, figsize=(15, 10))
# axes = axes.flatten()

# # Plot each operation in its own subplot
# for i, operation in enumerate(operations):
#     # Get data for this operation
#     op_data = df_n16[df_n16['operation'] == operation]
    
#     # Sort by attribute count
#     op_data = op_data.sort_values('attributes')
    
#     # Plot data
#     axes[i].plot(op_data['attributes'], op_data['mean_ms'], 
#                  marker='o', 
#                  color=colors[operation], 
#                  linewidth=2, 
#                  markersize=8)
    
#     # Set plot title and labels
#     axes[i].set_title(operation_display_names[operation], fontsize=14)
#     axes[i].set_xlabel('Number of Attributes (n)', fontsize=12)
#     axes[i].set_ylabel('Time (ms)', fontsize=12)
    
#     # Set x-axis to use attribute_counts
#     axes[i].set_xticks(attribute_counts)
#     axes[i].set_xticklabels(attribute_counts)
    
#     # Add grid
#     axes[i].grid(True, linestyle='--', alpha=0.7)

# # Set a common title for the entire figure
# fig.suptitle('T-SIRIS Performance (N=16, t=9) by Number of Attributes', fontsize=16)

# # Adjust layout
# plt.tight_layout(rect=[0, 0, 1, 0.95])  # Make room for the suptitle

# # Save the figure
# plt.savefig('t_siris_n16_performance.png', dpi=300, bbox_inches='tight')

# # Display the figure
# plt.show()















# # Colors for different operations
# colors = {
#     'obtain_master': '#E45932',  # Orange-Red
#     'issue_master': '#4A90E2',   # Blue
#     'obtain_context': '#50C878', # Green
#     'issue_context': '#8A2BE2',  # Different purple (BlueViolet)
#     'show': '#FFD700',           # Gold
#     'verify': '#4A90E2'          # Tomato
# }

# # Line styles for different operations
# line_styles = {
#     'obtain_master': '-',      # Solid
#     'issue_master': '-',       # Solid
#     'obtain_context': '--',     # Solid
#     'issue_context': '--',     # Dashed 
#     'show': '-',               # Solid
#     'verify': '--'              # Solid
# }

# markers = {
#     'obtain_master': 'o',     # Circle
#     'issue_master': 's',      # Square
#     'obtain_context': '^',    # Triangle up
#     'issue_context': 'd',     # Diamond
#     'show': 'p',              # Pentagon
#     'verify': '*'             # Star
# }

# # Create a single figure
# plt.figure(figsize=(10, 6))

# # Plot each operation
# for operation in operations:
#     # Get data for this operation
#     op_data = df_n16[df_n16['operation'] == operation]
    
#     # Sort by attribute count
#     op_data = op_data.sort_values('attributes')
    
#     # Plot data with appropriate line style
#     plt.plot(op_data['attributes'], op_data['mean_ms'], 
#              marker=markers[operation], 
#              color=colors[operation], 
#              linestyle=line_styles[operation],
#              linewidth=2, 
#              markersize=8,
#              label=operation_display_names[operation])

# # Set plot title and labels
# plt.title('T-SIRIS Performance (N=16, t=9)', fontsize=16)
# plt.xlabel('Number of Attributes (n)', fontsize=14)
# plt.ylabel('Time (ms)', fontsize=14)

# # Set x-axis to use attribute counts
# plt.xticks([4, 8, 16, 32, 64, 128])

# # Use logarithmic scale for y-axis
# # plt.yscale('log')

# # Add grid
# plt.grid(True, linestyle='--', alpha=0.7)

# # Add legend
# plt.legend(fontsize=12)

# # Show the plot
# plt.tight_layout()
# plt.savefig('t_siris_n16_all_operations.png', dpi=300, bbox_inches='tight')
# plt.show()












import matplotlib.pyplot as plt
import pandas as pd
import numpy as np

# List of operations to plot
operations = ['obtain_master', 'obtain_context', 'show',  'issue_master', 'issue_context', 'verify']

# More descriptive operation names for the plots
operation_display_names = {
    'obtain_master': 'Obtain Master',
    'issue_master': 'Issue Master',
    'obtain_context': 'Obtain Context',
    'issue_context': 'Issue Context',
    'show': 'Show',
    'verify': 'Verify'
}

# N values to compare
n_values = [4, 16, 64]

# Colors for different N values
n_colors = {
    4: '#E45932',   # Orange-Red
    16: '#4A90E2',  # Blue
    64: '#50C878'   # Green
}

# Line styles for different N values
n_markers = {
    4: 'o',     # Circle
    16: 's',    # Square
    64: '^'     # Triangle
}

# Create a figure with 2x3 subplots
fig, axes = plt.subplots(2, 3, figsize=(15, 10))
axes = axes.flatten()

# Attribute counts for x-axis
attribute_counts = [4, 8, 16, 32, 64, 128]

# Plot each operation in its own subplot
for i, operation in enumerate(operations):
    ax = axes[i]
    
    # For each N value
    for n in n_values:
        # Get data for this operation and N value
        op_data = df[(df['operation'] == operation) & (df['n_participants'] == n)]
        
        # Sort by attribute count
        op_data = op_data.sort_values('attributes')
        
        # Plot data
        ax.plot(op_data['attributes'], op_data['mean_ms'], 
                marker=n_markers[n], 
                color=n_colors[n], 
                linewidth=2, 
                markersize=8,
                label=f'N={n}, t={op_data.iloc[0]["threshold"]}')
    
    # Set plot title and labels
    ax.set_title(operation_display_names[operation], fontsize=14)
    ax.set_xlabel('Number of Attributes (n)', fontsize=12)
    ax.set_ylabel('Time (ms)', fontsize=12)
    
    # Set x-axis to use attribute_counts
    ax.set_xticks(attribute_counts)
    ax.set_xticklabels(attribute_counts)
    
    # Add grid
    ax.grid(True, linestyle='--', alpha=0.7)
    
    # Add legend to each subplot
    ax.legend(fontsize=10)
    
    # # Use log scale for operations with large variations
    # if operation in ['issue_master', 'issue_context']:
    #     ax.set_yscale('log')

# Set a common title for the entire figure
fig.suptitle('T-SIRIS Performance by Number of Attributes for Different N Values', fontsize=16)

# Adjust layout
plt.tight_layout(rect=[0, 0, 1, 0.95])  # Make room for the suptitle

# Save the figure
plt.savefig('t_siris_performance_by_n_values.png', dpi=300, bbox_inches='tight')

# Display the figure
plt.show()