from flask import Flask, request, jsonify
from datetime import datetime
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# List of puzzles
puzzles = [
    ("8d998e77c060f84f8b5754ed31093b21.ZWJLogdbzRU63mixAQwtkgAAAAAAAAAA0Op1J4JNfek=", 146),
    ("140b781425de19d5fef965201037169a.ZWJLowdbzRU63mixAQwtkgAAAAAAAAAAlyWoB61tDSI=", 146),
    ("eab70ea120262cb7231db7cf444e37e2.ZWJLpAdbzRU63mixAQwqkwAAAAAAAAAAAFAd/CHkJKo=", 147),
    ("61a5ae6cd2184c0411dd7f3ce8d60325.ZWJLpQdbzRU63mixAQwzkgAAAAAAAAAAxtF1N7/hSms=", 146),
    ("324f091b1f47fb21ed299e6af8eb0301.ZWJLpgdbzRU63mixAQwqlgAAAAAAAAAAVq/C2rYCSog=", 150),
    ("119622dcdde53542d3adcc8b3b9483a2.ZWJLpwdbzRU63mixAQwtlwAAAAAAAAAAitsEbKUYnEc=", 151),
    ("b916955243d3f64e0328513d03699360.ZWJLqQdbzRU63mixAQwtmQAAAAAAAAAAUbI2Day99G4=", 153),
    ("d9399604c1cd64c8b2457ca437e04052.ZWJLqgdbzRU63mixAQwwmgAAAAAAAAAAAWWCYxKqIio=", 154),
    ("be15d50c75fcd15e2f50327a55dec9d2.ZWJLqwdbzRU63mixAQwwnAAAAAAAAAAAFuKFl46XmBg=", 156),
    ("bcfa84f4f42ef6b26b5918767c928d6d.ZWJLrQdbzRU63mixAQwwngAAAAAAAAAARObt6PNKUi0=", 158),
    ("41fcce23c38ad436bd2e75657c37de3e.ZWJLrgdbzRU63mixAQwznwAAAAAAAAAAiwCxH1VWyZQ=", 159),
    ("c462426cbb30479cc622fb64bd60703d.ZWJLsAdbzRU63mixAQwqowAAAAAAAAAAANgYOBsMRhI=", 163),
    ("741b30798f5f1ec7561867feffb4afc0.ZWJLsgdbzRU63mixAQwwowAAAAAAAAAAAV/MgeTuBhk=", 163),
    ("4ac33c83d531dc5ee12a6ee467ce8939.ZWJLtAdbzRU63mixAQwqpgAAAAAAAAAAniJeNARoEiw=", 166),
    ("913a994a8c4cd4b33f1919aa3cd34228.ZWJLtgdbzRU63mixAQwwpgAAAAAAAAAAJ+cN8pTKUBQ=", 166),
    ("cb67bcf777002a7ce1b42553450fce0f.ZWJLuQdbzRU63mixAQwqqQAAAAAAAAAAXN3dHM2ql6w=", 169),
    ("424cfce9a33de9072733eedcbf33058e.ZWJLvAdbzRU63mixAQwqqgAAAAAAAAAAmudsI4ePcqU=", 170),
    ("7d8bab566a95154c12b55ab1f365648d.ZWJLwAdbzRU63mixAQwwqgAAAAAAAAAAFP+Ay2IiXOU=", 170),
    ("d4a3800df51776adfa86a4e801ee2541.ZWJLwwdbzRU63mixAQwwqwAAAAAAAAAAZBZ6a4QENOE=", 171),
    ("c0e37cd1245690af6e0e8ee4b5776d28.ZWJLxwdbzRU63mixAQwtrQAAAAAAAAAAJNKhexkFZwA=", 173),
    ("c3d855e2c718e5ff3dacd5e08761f882.ZWJLygdbzRU63mixAQwtrgAAAAAAAAAAPRjFC/v71NY=", 174),
    ("3434ec9314e0ee4702eedb111192f6b8.ZWJL0QdbzRU63mixAQwtrwAAAAAAAAAAP88dz6F08Sw=", 175),
    ("4c64dfbd5d591655671aba2edc927993.ZWJL1wdbzRU63mixAQwtsAAAAAAAAAAAjpfpuwuhEr0=", 176),
    ("dc190498bc2464885c864f1694a245b9.ZWJL3QdbzRU63mixAQwtsQAAAAAAAAAAlZBi51rP0Fg=", 177),
    ("902749896fe755c69546dc8ace6aef61.ZWJL4gdbzRU63mixAQwtsgAAAAAAAAAA+ZD5TnsoV7c=", 178),
    ("508a54657192bf8efcd8ed9c221bd07c.ZWJL6AdbzRU63mixAQwwsgAAAAAAAAAAKd5AyPTghVs=", 178),
    ("ae271124b4c3423fcaaa3bff8b46e06f.ZWJL7wdbzRU63mixAQwzsgAAAAAAAAAAWYmLaaywlUg=", 178),
    ("8af76103417c7e48fc0ab9ae67f55486.ZWJL9AdbzRU63mixAQwqtQAAAAAAAAAAuzgu5FIYsQ4=", 181)
]


class PuzzleManager:
    def __init__(self):
        self.puzzles = puzzles
        self.current_index = 0
        self.start_time = None
        self.last_puzzle_accessed = False

    def get_next_puzzle(self):
        if self.current_index == 0 and self.start_time is None:
            self.start_time = datetime.now()
            print(f"First puzzle requested at {self.start_time}")

        puzzle = self.puzzles[self.current_index]
        print(
            f"Puzzle {self.current_index + 1} of {len(self.puzzles)} --- Threshold: {puzzle[1]}")
        self.current_index += 1

        if self.current_index >= len(self.puzzles):
            self.current_index = 0
            self.last_puzzle_accessed = True
            print("Puzzle list reset to the beginning")

        return puzzle[0]

    def record_post_request(self):
        if self.start_time is not None and self.last_puzzle_accessed:
            end_time = datetime.now()
            time_diff = end_time - self.start_time
            print(f"Time elapsed: {time_diff}")
            self.start_time = None
            self.last_puzzle_accessed = False


puzzle_manager = PuzzleManager()


@app.route('/puzzle', methods=['GET', 'POST', 'OPTIONS'], provide_automatic_options=False)
def puzzle_route():
    if request.method == 'GET':
        puzzle = puzzle_manager.get_next_puzzle()
        return jsonify(data={"puzzle": puzzle}, success=True)
    elif request.method == 'POST':
        captcha_solution = request.form.get('frc-captcha-solution')
        if "8af76103417c7e48fc0ab9ae67f55486.ZWJL9AdbzRU63mixAQwqtQAAAAAAAAAAuzgu5FIYsQ4=" in captcha_solution:
            puzzle_manager.record_post_request()
        return ('', 200)
    elif request.method == 'OPTIONS':
        return ('', 204)


if __name__ == '__main__':
    app.run(debug=False, host='127.0.0.1', port=5000)
