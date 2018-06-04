from alignment.sequence import Sequence
from alignment.vocabulary import Vocabulary
from alignment.sequencealigner import SimpleScoring, GlobalSequenceAligner, LocalSequenceAligner
import importlib

def align(seq1, seq2):
  s1 = Sequence(seq1)
  s2 = Sequence(seq2)
  v = Vocabulary()
  s1Encoded = v.encodeSequence(s1)
  s2Encoded = v.encodeSequence(s2)
  return s1Encoded, s2Encoded, v

def score(aEncoded, bEncoded, v):
  scoring = SimpleScoring(1, -3)
  aligner = GlobalSequenceAligner(scoring, 0)
  #aligner = LocalSequenceAligner(scoring, -1)
  score, encodeds = aligner.align(aEncoded, bEncoded, backtrace=True)
  return score, encodeds

def dump(encodeds, v):
  for encoded in encodeds[0:1]:
    alignment = v.decodeSequenceAlignment(encoded)
    print alignment
    print 'Alignment score:', alignment.score
    print 'Percent identity:', alignment.percentIdentity()
    print

if __name__ == "__main__":
  sysdig = importlib.import_module('sysdig')
  sys = importlib.import_module('sys')
  #log1 = sysdig.parse(sys.argv[1])
  #log2 = sysdig.parse(sys.argv[2])
  #seq1 = [a[0] for a in log1]
  #seq2 = [a[0] for a in log2]
  seq1 = open(sys.argv[1],"r").read().split(" ")
  seq2 = open(sys.argv[2],"r").read().split(" ")
  print seq1, "\n", seq2
  enc1, enc2, v = align(seq1, seq2)
  print enc1, "\n", enc2
  out, encodes = score(enc1, enc2, v)
  dump(encodes, v)
