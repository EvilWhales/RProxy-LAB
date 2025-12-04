import pickle
from pynput import mouse, keyboard
import time

recorded_events = []

def on_move(x, y):
    print(f"Mouse moved to ({x}, {y})")
    recorded_events.append(("move", x, y, time.time()))

def on_click(x, y, button, pressed):
    if pressed:
        print(f"Mouse clicked at ({x}, {y}) with {button}")
        recorded_events.append(("click", x, y, button, time.time()))

def on_scroll(x, y, dx, dy):
    pass  # Implement if needed

def on_press(key):
    if key == keyboard.Key.esc:
        print("Escape key pressed - stopping.")
        return False  # Stop listener
    else:
        try:
            print(f"Key pressed: {key.char}")
            recorded_events.append(("keypress", key.char, time.time()))
        except AttributeError:
            print(f"Special key pressed: {key}")
            recorded_events.append(("keypress", str(key), time.time()))

def save_events(events):
    with open("mouse_events.pkl", "wb") as file:
        pickle.dump(events, file)
    print("Events saved to mouse_events.pkl.")

mouse_listener = mouse.Listener(on_move=on_move, on_click=on_click, on_scroll=on_scroll)
mouse_listener.start()

with keyboard.Listener(on_press=on_press) as listener:
    listener.join()

save_events(recorded_events)
