# To install NumPy via your command line first, run: pip install numpy
import numpy as np

# 1. Array Creation 
# Creating a 1D array from a Python list
array_1d = np.array([10, 20, 30, 40, 50])

# Creating a 2D array (a 3x3 matrix)
array_2d = np.array([[1, 2, 3], 
                     [4, 5, 6], 
                     [7, 8, 9]])

# Creating utility arrays
zeros_array = np.zeros((2, 3))       # 2x3 matrix filled with 0.0
range_array = np.arange(0, 10, 2)    # Numbers from 0 to 8 with a step of 2

# 2. Inspecting Attributes
print("--- Array Properties ---")
print(f"2D Array Dimensions: {array_2d.ndim}")  # Returns 2
print(f"2D Array Shape: {array_2d.shape}")      # Returns (3, 3)
print(f"2D Array Data Type: {array_2d.dtype}\n")# Returns int64 (or int32)

# 3. Indexing and Slicing
print("--- Indexing & Slicing ---")
print(f"First element of 1D array: {array_1d[0]}")
print(f"Extract a subset from 1D array: {array_1d[1:4]}")  # [20, 30, 40]
print(f"Extract specific element from 2D array (Row 1, Col 2): {array_2d[1, 2]}\n") # 6

# 4. Element-wise Math Operations (Vectorization)
print("--- Vectorized Operations ---")
modified_1d = array_1d * 2
print(f"1D array elements doubled: {modified_1d}")

# 5. Statistical Aggregations
print("\n--- Summary Statistics ---")
print(f"Sum of 2D array elements: {array_2d.sum()}")
print(f"Mean (Average) value of 2D array: {array_2d.mean()}")
print(f"Maximum value in 2D array: {array_2d.max()}")
