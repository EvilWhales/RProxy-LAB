import pickle
import time
from pynput.mouse import  Controller as MouseController
from pynput.keyboard import Controller as KeyboardController, Key

def replay_events(events):
    mouse_controller = MouseController()
    keyboard_controller = KeyboardController()
    start_time = None

    for event in events:
        event_type, *details = event
        if event_type in ["move", "click"]:
            x, y, *rest = details
            timestamp = rest[0] if event_type == "move" else rest[1]
        elif event_type == "keypress":
            key, timestamp = details

        if start_time is None:
            start_time = timestamp
            previous_timestamp = timestamp
        else:
            delay = timestamp - previous_timestamp
            time.sleep(delay)
            previous_timestamp = timestamp

        if event_type == "move":
            mouse_controller.position = (x, y)
            print(f"Moved to ({x}, {y})")
        elif event_type == "click":
            button = rest[0]
            mouse_controller.press(button)
            mouse_controller.release(button)
            print(f"Clicked at ({x}, {y}) with {button}")
        elif event_type == "keypress":
            try:
                keyboard_controller.press(key)
                keyboard_controller.release(key)
                print(f"Key pressed: {key}")
            except ValueError:
                special_key = getattr(Key, key, None)
                if special_key:
                    keyboard_controller.press(special_key)
                    keyboard_controller.release(special_key)
                    print(f"Special key pressed: {key}")

def load_events(filename):
    with open(filename, "rb") as file:
        return pickle.load(file)

if __name__ == '__main__':
    events = load_events("mouse_events.pkl")
    print("Starting replay.")
    replay_events(events)
