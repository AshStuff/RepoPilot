import matplotlib.pyplot as plt

# Data
categories = [
    "Annual Dev Time (Hours)",
    "Debugging Time (50%)",
    "Time Saved by Repopilot (25%)",
    "Estimated Cost Savings ($B)"
]
values = [
    1240,   # Total dev hours (millions)
    620,    # Debugging time (millions)
    155,    # Time saved by Repopilot (millions)
    7.75    # Cost savings in billions USD
]
colors = ['skyblue', 'orange', 'green', 'red']

# Create the bar chart
plt.figure(figsize=(10, 6))
bars = plt.bar(categories, values, color=colors)
plt.title("Impact of Repopilot on Developer Efficiency and Cost")
plt.ylabel("Millions of Hours / Billions USD")
plt.grid(axis='y', linestyle='--', alpha=0.7)

# Annotate bars with values
for bar in bars:
    yval = bar.get_height()
    if "Cost" in bar.get_label():
        plt.text(bar.get_x() + bar.get_width()/2, yval + 0.1, f"${yval:.2f}B", ha='center', va='bottom', fontsize=10)
    else:
        plt.text(bar.get_x() + bar.get_width()/2, yval + 10, f"{yval}M", ha='center', va='bottom', fontsize=10)

plt.tight_layout()
plt.savefig('./impact_of_repopilot.png')
plt.show()