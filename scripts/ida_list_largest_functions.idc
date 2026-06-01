// ida_list_largest_functions.idc
// File -> Script file...   Writes TSV: size, start, end, name (one .text function per line).
// Sort in Excel, column 1 (size) descending.
//
// get_next_func(start_of_fn) is BUGGY in some IDAs (returns the same start).
// Advance with get_next_func( FindFuncEnd(f) - 1 ) — last byte inside the function —

#include <idc.idc>

#define TEXT_SEG ".text"
#define OUT_NAME "ida_largest_functions.txt"
#define BADADDR 0xFFFFFFFF
#define ITER_SAFETY  500000
#define ITER_PROGBITS 0x1FFF  // 8191

static get_dir(idb) {
  auto n, i, c, out;
  n = strlen(idb);
  if (n < 1) {
    return ".\\";
  }
  out = ".\\";
  for (i = n - 1; i >= 0; i = i - 1) {
    c = substr(idb, i, i + 1);
    if (c == "\\" || c == "/") {
      out = substr(idb, 0, i + 1);
      break;
    }
  }
  return out;
}

// next function start after the function at f (works around get_next_func(entry) == entry)
static next_function_start(f) {
  auto fe, last, n;
  fe = FindFuncEnd(f);
  if (fe == BADADDR || fe <= f) {
    n = get_next_func(f + 1);
    if (n == f) {
      n = get_next_func(f);
    }
    return n;
  }
  last = fe - 1;
  if (last < f) {
    last = f;
  }
  n = get_next_func(last);
  if (n == f) {
    n = get_next_func(fe);
  }
  if (n == f) {
    n = get_next_func(f + 1);
  }
  if (n == f) {
    n = get_next_func(fe + 1);
  }
  return n;
}

static main() {
  auto f, fnext, s, fend, seg, idb, dir, path, fp, line, t;
  auto nout, iter, oldf;
  nout = 0;
  iter = 0;
  Message("ida_list: starting (use Output window for progress)\n");
  idb = get_idb_path();
  if (idb == 0 || strlen(idb) < 1) {
    idb = "x.idb";
  }
  dir = get_dir(idb);
  path = form("%s%s", dir, OUT_NAME);
  Message(form("ida_list: writing to %s\n", path));
  fp = fopen(path, "w");
  if (fp == 0) {
    line = form("Open failed: %s\n", path);
    Message(line);
    return 0;
  }
  line = "# all .text functions, unsorted. Sort column 1 (size) descending for largest.\n";
  fprintf(fp, form("%s", line));
  line = form("# segment %s  columns: size_hex, start, end, name\n", TEXT_SEG);
  fprintf(fp, form("%s", line));
  f = get_next_func(BADADDR);
  if (f == BADADDR) {
    f = get_next_func(0);
  }
  for (; f != BADADDR; ) {
    oldf = f;
    iter = iter + 1;
    if (iter > ITER_SAFETY) {
      Message("ida_list: safety cap, stopping with partial file\n");
      break;
    }
    if ((iter & ITER_PROGBITS) == 0) {
      Message(form("ida_list: %d iters, at %X, .text lines: %d\n", iter, f, nout));
    }
    fend = FindFuncEnd(f);
    seg = SegName(f);
    if (seg == TEXT_SEG) {
      if (fend != BADADDR) {
        s = fend - f;
        if (s > 0) {
          t = Name(f);
          if (t == 0) {
            t = " ";
          }
          if (strlen(t) < 1) {
            t = form("sub_%08X", f);
          }
          line = form("0x%08X\t0x%08X\t0x%08X\t%s\n", s, f, fend, t);
          fprintf(fp, form("%s", line));
          nout = nout + 1;
        }
      }
    }
    fnext = next_function_start(f);
    if (fnext == f || fnext == oldf) {
      Message("ida_list: cannot advance, stopping (partial file saved)\n");
      break;
    }
    f = fnext;
  }
  fclose(fp);
  line = form("ida_list: Wrote %d .text rows -> %s\n", nout, path);
  Message(line);
  return 0;
}
