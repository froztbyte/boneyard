#!/usr/bin/env python

''' decryption program for the variant vigenere cipher found in the
maryland coursera crypto-001 course. takes ciphertext 'ctext',
runs key guesses, picks out sentences with the most spaces in them,
spits out guessed plaintext (or, you know, explodes if any of these
assumptions don't hold '''

import collections

ctext = open('ctext', 'r').readlines()[0].strip()
all = {}

for keyl in range(1, 14):
    d = collections.defaultdict(int)
    for c in ctext[::keyl]:
        d[c] += 1
    all[keyl] = d


def calc_q(offset):
    ''' [(b[x]*1.0)/sum(b.values()) for x in b.keys()] '''
    ee = []
    t = 0
    sums = sum(offset.values())
    for i in offset.keys():
        t = (offset[i]) * 1.0 / sums
        ee.append(t ** 2)
    return sum(ee)


def findBytes(input):
    'this will iterate over the partial ciphertext for likely keys'
    guessed = {}
    for keyguess in range(0, 256):
        badbyte = False
        temp = []
        for s in input:
            if not badbyte:
                n = ord(s) ^ keyguess
                xor = chr(n)
                if (32 <= n <= 47) or (58 <= n <= 122):
                    temp.append(xor)
                    guessed[keyguess] = ''.join(temp)
                else:
                    badbyte = True
            else:
                break
    return guessed


max = {'num': -1, 'val': 0}
for item in all:
    c = calc_q(all[item])
    if c > max['val']:
        max['num'] = item
        max['val'] = c
    print "Offset %s has value %s " % (item, c)

print
print '''Keylen %s looks most likely (%s), continuing with attempted \
ciphertext decryption''' % (max['num'], max['val'])

keys, ith = {}, {}
counters = {}
bytes = ctext.decode('hex')

for i in range(0, max['num']):
    counters[i] = bytes[i::max['num']]
    ith[i] = findBytes(counters[i])

codeslot = {}
for i in ith:
    spc = 0
    for item in ith[i]:
        count = len([x for x in ith[i][item] if x == ' '])
        if count > spc:
            spc = count
            codeslot[i] = ith[i][item]

deco = ''.join([''.join(x) for x in zip(*[codeslot[x] for
                                          x in codeslot.keys()])])
print deco
