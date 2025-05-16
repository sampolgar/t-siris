import matplotlib.pyplot as plt

# Attribute counts for all readings
attribute_counts = [4, 8, 16, 32, 64, 128]

# Operation data
data = {
    "token_request": {
        "tUTT Our Construction": [1.64, 3.20, 5.94, 11.67, 22.85, 45.01],
        "tACT": [8.55, 17.44, 37.15, 75.19, 135.91, 281.95]
    },
    "t_issue": {
        "tUTT_no_zkp_verify": [5.73, 10.28, 19.38, 37.64, 74.11, 148.57],
        "tUTT_with_zkp_verify": [20.18, 34.49, 62.97, 120.82, 230.60, 456.58],
        "tACT": [3.09, 6.57, 14.14, 27.81, 61.34, 116.14]
    },
    "aggregate": {
        "tUTT_no_zkp_verify": [1.04, 1.05, 1.27, 1.21, 1.39, 1.66],  # Extended from your sample
        "tUTT_with_zkp_verify": [30.29, 43.58, 69.12, 122.01, 234.77, 459.31],  # Full data
        "tACT": [3.92, 6.45, 15.04, 29.33, 52.55, 109.71]  # aggregate_unblind for tACT
    },
    "prove": {
        "tUTT Our Construction": [1.21, 1.26, 1.32, 1.49, 1.64, 2.00],
        "tACT": [7.90, 10.03, 15.78, 23.11, 40.56, 73.03]
    },
    "verify": {
        "tUTT Our Construction": [1.74, 1.70, 1.72, 1.72, 1.69, 1.73],
        "tACT": [11.20, 16.83, 26.64, 41.20, 74.07, 138.99]
    }
}

# Custom display names for operations
display_names = {
    "token_request": "tPrepare",
    "t_issue": "tShareSign",
    "aggregate": "tAggregate",
    "prove": "Show",
    "verify": "Verify"
}

# Colors for schemes
colors = {
    "tUTT Our Construction": "#50C878",       # Orange-Red for tUTT
    "tUTT_no_zkp_verify": "#50C878", # Same color for aggregate variants
    "tUTT_with_zkp_verify": "#D6BC8E",
    "tACT": "#E45932"          # Light Blue for tACT
}

# Markers to distinguish schemes
markers = {
    "tUTT Our Construction": 's',       # Square for tUTT
    "tUTT_no_zkp_verify": 's',
    "tUTT_with_zkp_verify": 's',
    "tACT": 'o'          # Circle for tACT
}

# # Generate plots for each operation
# for op_key, op_data in data.items():
#     plt.figure(figsize=(6, 4))
#     # Use the custom display name
#     display_name = display_names.get(op_key, op_key)
#     for scheme, timings in op_data.items():
#         # Clean up scheme names for legend (e.g., "tUTT No Verify")
#         label = scheme.replace("_", " ")
#         plt.plot(attribute_counts, timings, marker=markers[scheme], label=label, color=colors[scheme])
#     plt.title(f'{display_name} (N=16, t=9)')
#     plt.xlabel('Number of Attributes (n)')
#     plt.ylabel('Time (ms)')
#     plt.legend()
#     plt.grid(True)
#     plt.tight_layout()
#     plt.show()

    # Create a 2x3 grid of subplots
fig, axes = plt.subplots(2, 3, figsize=(12, 8))  # Compact size for minipage-like feel

# Flatten axes array for easier iteration
axes = axes.flatten()

# List of operations to plot
operations = list(data.keys())

# Plot each operation in its own subplot
for i, op_key in enumerate(operations):
    ax = axes[i]
    op_data = data[op_key]
    display_name = display_names.get(op_key, op_key)
    for scheme, timings in op_data.items():
        label = scheme.replace("_", " ")
        ax.plot(attribute_counts, timings, marker=markers[scheme], label=label, color=colors[scheme])
    ax.set_title(display_name, fontsize=14)
    ax.set_xlabel('Attributes (n)', fontsize=12)
    ax.set_ylabel('Time (ms)', fontsize=12)
    ax.legend(fontsize=10)
    ax.grid(True)
    ax.tick_params(axis='both', labelsize=10)

# Hide the unused subplot (bottom-right, index 5)
axes[5].axis('off')

# Adjust layout to prevent overlap
plt.tight_layout()

plt.savefig('chap5_tutt_scale_by_n_attributes.png')

# Display the figure
plt.show()