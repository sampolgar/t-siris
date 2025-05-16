import matplotlib.pyplot as plt

# Node counts and corresponding thresholds
node_counts = [4, 16, 64]
thresholds = [3, 9, 33]  # Corresponding t values

# Operation data for n=16
data = {
    "token_request": {
        "tUTT Our Construction": [5.909607806837892, 5.94213946397675, 6.329100165035636],
        "tACT": [33.839707905000004, 37.146817299999995, 36.10963501]
    },
    "t_issue": {
        "tUTT_no_verify": [6.474419530388201, 19.378794349090903, 71.94679027333332],
        "tUTT_with_verify": [20.812308716, 62.9739280275, 233.06373168000002],
        "tACT": [13.684414474999999, 14.139394375, 13.5221063475]
    },
    "aggregate": {
        "tUTT_no_verify": [0.5384226587171513, 1.2675665675772834, 4.825925287496702],
        "tUTT_with_verify": [23.565276614444443, 69.12156123999998, 251.13809331000002],
        "tACT": [6.4592886975, 15.036417825, 41.020374784999994]
    },
    "prove": {
        "tUTT Our Construction": [1.3292043694675286, 1.315715893138752, 1.318371701842062],
        "tACT": [14.6698589475, 15.779801557499999, 14.554870939999999]
    },
    "verify": {
        "tUTT Our Construction": [1.7007060780348866, 1.7217594481649328, 1.6817327874479253],
        "tACT": [23.51304304666667, 26.638938715, 25.02735127]
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
    "tUTT Our Construction": "#50C878",       # green
    "tUTT_no_verify": "#50C878",              # Same color for no-verify variants
    "tUTT_with_verify": "#D6BC8E",            # Light beige for with-verify
    "tACT": "#E45932"                             # Light Blue for tACT
}



# Markers to distinguish schemes
markers = {
    "tUTT Our Construction": 's',       # Square for tUTT
    "tUTT_no_verify": 's',
    "tUTT_with_verify": 's',
    "tACT": 'o'          # Circle for tACT
}

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
        ax.plot(node_counts, timings, marker=markers[scheme], label=label, color=colors[scheme])
    ax.set_title(display_name, fontsize=13)
    ax.set_xlabel('Nodes (N)', fontsize=11)
    ax.set_ylabel('Time (ms)', fontsize=11)
    # Use logarithmic scale for t_issue and aggregate_with_verify due to large time ranges
    if op_key in ["t_issue", "aggregate"]:
        ax.set_yscale('log')
    ax.legend(fontsize=10)
    ax.grid(True)
    ax.tick_params(axis='both', labelsize=10)
    # Set x-ticks to node counts
    ax.set_xticks(node_counts)
    ax.set_xticklabels([f'N={n}, t={t}' for n, t in zip(node_counts, thresholds)], rotation=45)

# Hide the unused subplot (bottom-right, index 5)
axes[5].axis('off')

# Adjust layout to prevent overlap
plt.tight_layout()

# Save the figure for inclusion in LaTeX
plt.savefig('chap5_tutt_scale_by_N_nodes.png')

# Display the figure
plt.show()