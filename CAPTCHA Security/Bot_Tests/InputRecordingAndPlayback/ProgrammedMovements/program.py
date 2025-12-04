from pynput.mouse import Controller as MouseController, Button
import time

# Initialize mouse controller
mouse = MouseController()

# Set the start and target coordinates here
start_x_coordinate_1 = 3000
start_y_coordinate_1 = 780
target_x_coordinate_1 = 3767  
target_y_coordinate_1 = 780

target_x_coordinate_2 = 3934
target_y_coordinate_2 = 1000


# Function to move the cursor in a line to the target coordinates
def move_cursor(start_x, start_y, target_x, target_y):
    mouse.position = (start_x, start_y) 

    x_direction = 1 if target_x > start_x else -1
    y_direction = 1 if target_y > start_y else -1

    distance_x = abs(target_x - start_x)
    distance_y = abs(target_y - start_y)

    max_distance = max(distance_x, distance_y)

    step_size_x = x_direction * (distance_x / max_distance)
    step_size_y = y_direction * (distance_y / max_distance)

    for _ in range(int(max_distance)):
        new_x = mouse.position[0] + step_size_x
        new_y = mouse.position[1] + step_size_y
        mouse.position = (new_x, new_y)

    mouse.position = (target_x, target_y) 
    mouse.click(Button.left, 1) 

# Perform the first line of movement and click
move_cursor(start_x_coordinate_1, start_y_coordinate_1, target_x_coordinate_1, target_y_coordinate_1)

 # Slight delay between the movements
time.sleep(1) 

move_cursor(target_x_coordinate_1, target_y_coordinate_1, target_x_coordinate_2, target_y_coordinate_2)


# Jump mouse
# mouse.position = (target_x_coordinate_2, target_y_coordinate_2)
# mouse.click(Button.left, 1)