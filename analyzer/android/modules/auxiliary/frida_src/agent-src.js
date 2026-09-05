import Java from "frida-java-bridge";

const PID = Process.id;
const MAX_PREVIEW = 256;
const NATIVE_EVENT_CAP = 16;

function preview(value) {
  if (value === null || value === undefined) {
    return null;
  }
  let s;
  try {
    s = typeof value === "string" ? value : String(value);
  } catch (e) {
    return "<unprintable>";
  }
  return s.length > MAX_PREVIEW ? s.slice(0, MAX_PREVIEW) + "...(truncated)" : s;
}

function emit(className, methodName, args, retval) {
  send({
    ts: Date.now() / 1000,
    pid: PID,
    class: className,
    method: methodName,
    args_preview: args.map(preview),
    retval_preview: preview(retval),
  });
}

function hookMethod(className, methodName, overloadArgTypes) {
  const target = Java.use(className);
  const method = overloadArgTypes ? target[methodName].overload(...overloadArgTypes) : target[methodName];
  const original = method.implementation;
  method.implementation = function (...args) {
    let retval;
    let threw = null;
    try {
      retval = original ? original.apply(this, args) : this[methodName](...args);
    } catch (e) {
      threw = e;
    }
    try {
      emit(className, methodName, args, threw ? `<exception: ${threw}>` : retval);
    } catch (e) {
      // never let logging break the hooked call
    }
    if (threw) {
      throw threw;
    }
    return retval;
  };
}

function hookAllOverloads(className, methodName) {
  const target = Java.use(className);
  const overloads = target[methodName].overloads;
  overloads.forEach((ov) => {
    const original = ov.implementation;
    ov.implementation = function (...args) {
      let retval;
      let threw = null;
      try {
        retval = original ? original.apply(this, args) : ov.apply(this, args);
      } catch (e) {
        threw = e;
      }
      try {
        emit(className, methodName, args, threw ? `<exception: ${threw}>` : retval);
      } catch (e) {
        // never let logging break the hooked call
      }
      if (threw) {
        throw threw;
      }
      return retval;
    };
  });
}

function safeHook(label, fn) {
  try {
    fn();
    send({ ts: Date.now() / 1000, pid: PID, class: null, method: null, hook_status: `${label}: installed` });
  } catch (e) {
    send({ ts: Date.now() / 1000, pid: PID, class: null, method: null, hook_status: `${label}: failed - ${e}` });
  }
}

function resolveExport(moduleName, symbol) {
  try {
    return Process.getModuleByName(moduleName).getExportByName(symbol);
  } catch (e) {
    try {
      return Module.getGlobalExportByName(symbol);
    } catch (e2) {
      return null;
    }
  }
}

function hookNativeOpen() {
  const attach = globalThis.Interceptor && globalThis.Interceptor.attach;
  if (typeof attach !== "function") {
    throw new Error(`Interceptor.attach is ${typeof attach}`);
  }
  const candidates = [
    { name: "open", pathArg: 0 },
    { name: "openat", pathArg: 1 },
  ];
  for (const { name, pathArg } of candidates) {
    const ptr = resolveExport("libc.so", name);
    if (!ptr) {
      continue;
    }
    let count = 0;
    attach.call(globalThis.Interceptor, ptr, {
      onEnter(args) {
        if (count >= NATIVE_EVENT_CAP) {
          return;
        }
        count += 1;
        let path;
        try {
          path = args[pathArg].readUtf8String();
        } catch (e) {
          path = "<unreadable>";
        }
        send({
          ts: Date.now() / 1000,
          pid: PID,
          class: "libc.so",
          method: name,
          args_preview: [path],
          retval_preview: null,
        });
      },
    });
    send({ ts: Date.now() / 1000, pid: PID, class: null, method: null, hook_status: `libc.so!${name}: installed` });
    return;
  }
  throw new Error("libc.so open/openat not found");
}

function emitAlreadyResumedActivities() {
  let found = 0;
  Java.choose("android.app.Activity", {
    onMatch(instance) {
      found += 1;
      emit("android.app.Activity", "onResume", ["<already-resumed>"], instance.getClass().getName());
    },
    onComplete() {
      send({
        ts: Date.now() / 1000,
        pid: PID,
        class: null,
        method: null,
        hook_status: `Activity.enumerate: ${found} instance(s)`,
      });
    },
  });
}

function hookInterestingFileExists() {
  const File = Java.use("java.io.File");
  const original = File.exists.implementation;
  File.exists.implementation = function () {
    const ret = original ? original.call(this) : this.exists();
    try {
      const path = this.getAbsolutePath();
      if (/su$|magisk|busybox|Superuser|sbin\/su|which/i.test(String(path))) {
        emit("java.io.File", "exists", [path], ret);
      }
    } catch (e) {
      // never let logging break exists()
    }
    return ret;
  };
}

function clickFirstFab() {
  const names = [
    "com.google.android.material.floatingactionbutton.FloatingActionButton",
    "android.support.design.widget.FloatingActionButton",
  ];
  let clicked = 0;
  for (const name of names) {
    try {
      Java.use(name);
    } catch (e) {
      continue;
    }
    Java.choose(name, {
      onMatch(instance) {
        try {
          instance.performClick();
          clicked += 1;
          emit(name, "performClick", [], true);
        } catch (e) {
          // keep looking
        }
      },
      onComplete() {},
    });
    if (clicked) {
      return;
    }
  }
  throw new Error("no FloatingActionButton instance");
}

safeHook("libc.so!open", hookNativeOpen);

Java.perform(function () {
  safeHook("Activity.onResume", () => hookMethod("android.app.Activity", "onResume"));
  safeHook("Runtime.exec", () => hookAllOverloads("java.lang.Runtime", "exec"));
  safeHook("Runtime.loadLibrary", () => hookAllOverloads("java.lang.Runtime", "loadLibrary"));
  safeHook("Runtime.load", () => hookAllOverloads("java.lang.Runtime", "load"));
  safeHook("Intent.getAction", () => hookAllOverloads("android.content.Intent", "getAction"));
  safeHook("Intent.setAction", () => hookAllOverloads("android.content.Intent", "setAction"));
  safeHook("Intent.getData", () => hookAllOverloads("android.content.Intent", "getData"));
  safeHook("Intent.setData", () => hookAllOverloads("android.content.Intent", "setData"));
  safeHook("Cipher.doFinal", () => {
    hookMethod("javax.crypto.Cipher", "doFinal", ["[B"]);
  });
  safeHook("File.exists", hookInterestingFileExists);

  setTimeout(() => {
    Java.perform(() => safeHook("Activity.enumerate", emitAlreadyResumedActivities));
  }, 2000);

  // Sample UIs (RootBeer, many others) only run payload work on a FAB
  // click. performClick is generic and does not hard-code an APK.
  setTimeout(() => {
    Java.perform(() => safeHook("FAB.performClick", clickFirstFab));
  }, 5000);
});
