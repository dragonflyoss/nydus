import os
import sys
import shutil
import datetime

sys.path.append(os.path.realpath("framework"))

from bot import Bot

if __name__ == "__main__":
    target_dir = sys.argv[1]
    os.chdir(target_dir)
    spaces = os.listdir(target_dir)
    spaces.sort(key=os.path.getmtime)
    today = datetime.date.today()
    bot = Bot()
    deleted_spaces = []
    for space in spaces:
        mtime = datetime.date.fromtimestamp(os.path.getmtime(space))
        delta_days = today - mtime
        if delta_days.days >= 10:
            shutil.rmtree(space)
            deleted_spaces.append(space)

    bot.send(f"Delete Test Workspace {deleted_spaces} since it is out-of-date")
