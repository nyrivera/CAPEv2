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

function hookNativeOpen() {
  const candidates = [
    { name: "open", pathArg: 0 },
    { name: "openat", pathArg: 1 },
  ];
  for (const { name, pathArg } of candidates) {
    const ptr = Module.findExportByName("libc.so", name);
    if (!ptr) {
      continue;
    }
    let count = 0;
    Interceptor.attach(ptr, {
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
  safeHook("Activity.enumerate", emitAlreadyResumedActivities);
});
