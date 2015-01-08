/*
    This file is part of generate_character_ram
    Copyright (C) 2012  Julien Thevenon ( julien_thevenon at yahoo.fr )

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>
*/
#include "my_bmp.h"
#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <iomanip>

int main(int argc, char ** argv)
{
  std::cout << argc << " parameters" << std::endl ;
  if(argc != 2)
    {
      std::cout << "Error you must provide a list the input file name as parameter" << std::endl ;
      exit(-1);
    }
  my_bmp l_input_bmp(argv[1]);
  const uint32_t l_size_min = 153;
  uint32_t l_width = l_input_bmp.get_width();
  uint32_t l_height = l_input_bmp.get_height();
  std::cout << "Width = " << l_width << std::endl ;
  std::cout << "Heigth = " << l_height << std::endl ;
  if(l_width < l_size_min || l_height < l_size_min)
    {
      std::cout << "Error image must be at least 153*153" << std::endl ;
      exit(-1);
    }

  std::ofstream l_output_file;
  l_output_file.open("character_rom.coe");
  if(l_output_file == NULL)
    {
      std::cout << "Error unabled to open output file " << std::endl ;
      exit(-1);
    }

  l_output_file << "memory_initialization_radix=2;" << std::endl ;
  l_output_file << "memory_initialization_vector= " << std::endl ;

  for(uint32_t l_line = 0; l_line < 16 ; ++l_line)
    {
      uint32_t l_y_min = (l_line +1 ) * 9;
      for(uint32_t l_column = 0; l_column < 16 ; ++l_column)
	{
	  uint32_t l_x_min = (l_column +1 ) * 9;
#ifdef DEBUG
	  std::cout << "Generate object(" << std::hex << l_column << "," << l_line << ")" << std::dec << std::endl ;
	  std:: cout << "Starting from coordinate (" << l_x_min << "," << l_y_min << ")" << std::endl ;
#endif
	  for(uint32_t l_y = l_y_min ; l_y < l_y_min + 8 ; ++l_y)
	    {
	      for(uint32_t l_x = l_x_min ; l_x < l_x_min + 8 ; ++l_x)
		{
		  my_color l_black(0,0,0);
		  my_color_alpha l_color = l_input_bmp.get_pixel_color(l_x,l_y);
#ifdef DEBUG
		  l_color.display();
		  std::cout << " " << (l_color == l_black ? "false" : "true" ) << std::endl ;
#endif
		  if(l_color == l_black)
		    {
		      l_output_file << "1" ;
		    }
		  else
		    {
		      l_output_file << "0" ;
		    }
		} 
	      l_output_file << (l_line != 15 || l_column != 15 || l_y != l_y_min + 7 ? "," : ";" ) << std::endl ;
	    }
	  l_output_file << std::endl ;
	}
    }
  l_output_file.close();
  std::cout << "Generation successfull" << std::endl ;




  my_color_alpha** m_colors = new my_color_alpha*[256];

  m_colors[0] = new my_color_alpha(  0,  0,  0,   0);
  m_colors[1] = new my_color_alpha(128,  0,  0,   0);
  m_colors[2] = new my_color_alpha(  0,128,  0,   0);
  m_colors[3] = new my_color_alpha(128,128,  0,   0);
  m_colors[4] = new my_color_alpha(  0,  0,128,   0);
  m_colors[5] = new my_color_alpha(128,  0,128,   0);
  m_colors[6] = new my_color_alpha(  0,128,128,   0);
  m_colors[7] = new my_color_alpha(192,192,192,   0);
  m_colors[8] = new my_color_alpha(192,220,192,   0);
  m_colors[9] = new my_color_alpha(166,202,240,   0);
  m_colors[10] = new my_color_alpha( 64, 32,  0,   0);
  m_colors[11] = new my_color_alpha( 96, 32,  0,   0);
  m_colors[12] = new my_color_alpha(128, 32,  0,   0);
  m_colors[13] = new my_color_alpha(160, 32,  0,   0);
  m_colors[14] = new my_color_alpha(192, 32,  0,   0);
  m_colors[15] = new my_color_alpha(224, 32,  0,   0);
  m_colors[16] = new my_color_alpha(  0, 64,  0,   0);
  m_colors[17] = new my_color_alpha( 32, 64,  0,   0);
  m_colors[18] = new my_color_alpha( 64, 64,  0,   0);
  m_colors[19] = new my_color_alpha( 96, 64,  0,   0);
  m_colors[20] = new my_color_alpha(128, 64,  0,   0);
  m_colors[21] = new my_color_alpha(160, 64,  0,   0);
  m_colors[22] = new my_color_alpha(192, 64,  0,   0);
  m_colors[23] = new my_color_alpha(224, 64,  0,   0);
  m_colors[24] = new my_color_alpha(  0, 96,  0,   0);
  m_colors[25] = new my_color_alpha( 32, 96,  0,   0);
  m_colors[26] = new my_color_alpha( 64, 96,  0,   0);
  m_colors[27] = new my_color_alpha( 96, 96,  0,   0);
  m_colors[28] = new my_color_alpha(128, 96,  0,   0);
  m_colors[29] = new my_color_alpha(160, 96,  0,   0);
  m_colors[30] = new my_color_alpha(192, 96,  0,   0);
  m_colors[31] = new my_color_alpha(224, 96,  0,   0);
  m_colors[32] = new my_color_alpha(  0,128,  0,   0);
  m_colors[33] = new my_color_alpha( 32,128,  0,   0);
  m_colors[34] = new my_color_alpha( 64,128,  0,   0);
  m_colors[35] = new my_color_alpha( 96,128,  0,   0);
  m_colors[36] = new my_color_alpha(128,128,  0,   0);
  m_colors[37] = new my_color_alpha(160,128,  0,   0);
  m_colors[38] = new my_color_alpha(192,128,  0,   0);
  m_colors[39] = new my_color_alpha(224,128,  0,   0);
  m_colors[40] = new my_color_alpha(  0,160,  0,   0);
  m_colors[41] = new my_color_alpha( 32,160,  0,   0);
  m_colors[42] = new my_color_alpha( 64,160,  0,   0);
  m_colors[43] = new my_color_alpha( 96,160,  0,   0);
  m_colors[44] = new my_color_alpha(128,160,  0,   0);
  m_colors[45] = new my_color_alpha(160,160,  0,   0);
  m_colors[46] = new my_color_alpha(192,160,  0,   0);
  m_colors[47] = new my_color_alpha(224,160,  0,   0);
  m_colors[48] = new my_color_alpha(  0,192,  0,   0);
  m_colors[49] = new my_color_alpha( 32,192,  0,   0);
  m_colors[50] = new my_color_alpha( 64,192,  0,   0);
  m_colors[51] = new my_color_alpha( 96,192,  0,   0);
  m_colors[52] = new my_color_alpha(128,192,  0,   0);
  m_colors[53] = new my_color_alpha(160,192,  0,   0);
  m_colors[54] = new my_color_alpha(192,192,  0,   0);
  m_colors[55] = new my_color_alpha(224,192,  0,   0);
  m_colors[56] = new my_color_alpha(  0,224,  0,   0);
  m_colors[57] = new my_color_alpha( 32,224,  0,   0);
  m_colors[58] = new my_color_alpha( 64,224,  0,   0);
  m_colors[59] = new my_color_alpha( 96,224,  0,   0);
  m_colors[60] = new my_color_alpha(128,224,  0,   0);
  m_colors[61] = new my_color_alpha(160,224,  0,   0);
  m_colors[62] = new my_color_alpha(192,224,  0,   0);
  m_colors[63] = new my_color_alpha(224,224,  0,   0);
  m_colors[64] = new my_color_alpha(  0,  0, 64,   0);
  m_colors[65] = new my_color_alpha( 32,  0, 64,   0);
  m_colors[66] = new my_color_alpha( 64,  0, 64,   0);
  m_colors[67] = new my_color_alpha( 96,  0, 64,   0);
  m_colors[68] = new my_color_alpha(128,  0, 64,   0);
  m_colors[69] = new my_color_alpha(160,  0, 64,   0);
  m_colors[70] = new my_color_alpha(192,  0, 64,   0);
  m_colors[71] = new my_color_alpha(224,  0, 64,   0);
  m_colors[72] = new my_color_alpha(  0, 32, 64,   0);
  m_colors[73] = new my_color_alpha( 32, 32, 64,   0);
  m_colors[74] = new my_color_alpha( 64, 32, 64,   0);
  m_colors[75] = new my_color_alpha( 96, 32, 64,   0);
  m_colors[76] = new my_color_alpha(128, 32, 64,   0);
  m_colors[77] = new my_color_alpha(160, 32, 64,   0);
  m_colors[78] = new my_color_alpha(192, 32, 64,   0);
  m_colors[79] = new my_color_alpha(224, 32, 64,   0);
  m_colors[80] = new my_color_alpha(  0, 64, 64,   0);
  m_colors[81] = new my_color_alpha( 32, 64, 64,   0);
  m_colors[82] = new my_color_alpha( 64, 64, 64,   0);
  m_colors[83] = new my_color_alpha( 96, 64, 64,   0);
  m_colors[84] = new my_color_alpha(128, 64, 64,   0);
  m_colors[85] = new my_color_alpha(160, 64, 64,   0);
  m_colors[86] = new my_color_alpha(192, 64, 64,   0);
  m_colors[87] = new my_color_alpha(224, 64, 64,   0);
  m_colors[88] = new my_color_alpha(  0, 96, 64,   0);
  m_colors[89] = new my_color_alpha( 32, 96, 64,   0);
  m_colors[90] = new my_color_alpha( 64, 96, 64,   0);
  m_colors[91] = new my_color_alpha( 96, 96, 64,   0);
  m_colors[92] = new my_color_alpha(128, 96, 64,   0);
  m_colors[93] = new my_color_alpha(160, 96, 64,   0);
  m_colors[94] = new my_color_alpha(192, 96, 64,   0);
  m_colors[95] = new my_color_alpha(224, 96, 64,   0);
  m_colors[96] = new my_color_alpha(  0,128, 64,   0);
  m_colors[97] = new my_color_alpha( 32,128, 64,   0);
  m_colors[98] = new my_color_alpha( 64,128, 64,   0);
  m_colors[99] = new my_color_alpha( 96,128, 64,   0);
  m_colors[100] = new my_color_alpha(128,128, 64,   0);
  m_colors[101] = new my_color_alpha(160,128, 64,   0);
  m_colors[102] = new my_color_alpha(192,128, 64,   0);
  m_colors[103] = new my_color_alpha(224,128, 64,   0);
  m_colors[104] = new my_color_alpha(  0,160, 64,   0);
  m_colors[105] = new my_color_alpha( 32,160, 64,   0);
  m_colors[106] = new my_color_alpha( 64,160, 64,   0);
  m_colors[107] = new my_color_alpha( 96,160, 64,   0);
  m_colors[108] = new my_color_alpha(128,160, 64,   0);
  m_colors[109] = new my_color_alpha(160,160, 64,   0);
  m_colors[110] = new my_color_alpha(192,160, 64,   0);
  m_colors[111] = new my_color_alpha(224,160, 64,   0);
  m_colors[112] = new my_color_alpha(  0,192, 64,   0);
  m_colors[113] = new my_color_alpha( 32,192, 64,   0);
  m_colors[114] = new my_color_alpha( 64,192, 64,   0);
  m_colors[115] = new my_color_alpha( 96,192, 64,   0);
  m_colors[116] = new my_color_alpha(128,192, 64,   0);
  m_colors[117] = new my_color_alpha(160,192, 64,   0);
  m_colors[118] = new my_color_alpha(192,192, 64,   0);
  m_colors[119] = new my_color_alpha(224,192, 64,   0);
  m_colors[120] = new my_color_alpha(  0,224, 64,   0);
  m_colors[121] = new my_color_alpha( 32,224, 64,   0);
  m_colors[122] = new my_color_alpha( 64,224, 64,   0);
  m_colors[123] = new my_color_alpha( 96,224, 64,   0);
  m_colors[124] = new my_color_alpha(128,224, 64,   0);
  m_colors[125] = new my_color_alpha(160,224, 64,   0);
  m_colors[126] = new my_color_alpha(192,224, 64,   0);
  m_colors[127] = new my_color_alpha(224,224, 64,   0);
  m_colors[128] = new my_color_alpha(  0,  0,128,   0);
  m_colors[129] = new my_color_alpha( 32,  0,128,   0);
  m_colors[130] = new my_color_alpha( 64,  0,128,   0);
  m_colors[131] = new my_color_alpha( 96,  0,128,   0);
  m_colors[132] = new my_color_alpha(128,  0,128,   0);
  m_colors[133] = new my_color_alpha(160,  0,128,   0);
  m_colors[134] = new my_color_alpha(192,  0,128,   0);
  m_colors[135] = new my_color_alpha(224,  0,128,   0);
  m_colors[136] = new my_color_alpha(  0, 32,128,   0);
  m_colors[137] = new my_color_alpha( 32, 32,128,   0);
  m_colors[138] = new my_color_alpha( 64, 32,128,   0);
  m_colors[139] = new my_color_alpha( 96, 32,128,   0);
  m_colors[140] = new my_color_alpha(128, 32,128,   0);
  m_colors[141] = new my_color_alpha(160, 32,128,   0);
  m_colors[142] = new my_color_alpha(192, 32,128,   0);
  m_colors[143] = new my_color_alpha(224, 32,128,   0);
  m_colors[144] = new my_color_alpha(  0, 64,128,   0);
  m_colors[145] = new my_color_alpha( 32, 64,128,   0);
  m_colors[146] = new my_color_alpha( 64, 64,128,   0);
  m_colors[147] = new my_color_alpha( 96, 64,128,   0);
  m_colors[148] = new my_color_alpha(128, 64,128,   0);
  m_colors[149] = new my_color_alpha(160, 64,128,   0);
  m_colors[150] = new my_color_alpha(192, 64,128,   0);
  m_colors[151] = new my_color_alpha(224, 64,128,   0);
  m_colors[152] = new my_color_alpha(  0, 96,128,   0);
  m_colors[153] = new my_color_alpha( 32, 96,128,   0);
  m_colors[154] = new my_color_alpha( 64, 96,128,   0);
  m_colors[155] = new my_color_alpha( 96, 96,128,   0);
  m_colors[156] = new my_color_alpha(128, 96,128,   0);
  m_colors[157] = new my_color_alpha(160, 96,128,   0);
  m_colors[158] = new my_color_alpha(192, 96,128,   0);
  m_colors[159] = new my_color_alpha(224, 96,128,   0);
  m_colors[160] = new my_color_alpha(  0,128,128,   0);
  m_colors[161] = new my_color_alpha( 32,128,128,   0);
  m_colors[162] = new my_color_alpha( 64,128,128,   0);
  m_colors[163] = new my_color_alpha( 96,128,128,   0);
  m_colors[164] = new my_color_alpha(128,128,128,   0);
  m_colors[165] = new my_color_alpha(160,128,128,   0);
  m_colors[166] = new my_color_alpha(192,128,128,   0);
  m_colors[167] = new my_color_alpha(224,128,128,   0);
  m_colors[168] = new my_color_alpha(  0,160,128,   0);
  m_colors[169] = new my_color_alpha( 32,160,128,   0);
  m_colors[170] = new my_color_alpha( 64,160,128,   0);
  m_colors[171] = new my_color_alpha( 96,160,128,   0);
  m_colors[172] = new my_color_alpha(128,160,128,   0);
  m_colors[173] = new my_color_alpha(160,160,128,   0);
  m_colors[174] = new my_color_alpha(192,160,128,   0);
  m_colors[175] = new my_color_alpha(224,160,128,   0);
  m_colors[176] = new my_color_alpha(  0,192,128,   0);
  m_colors[177] = new my_color_alpha( 32,192,128,   0);
  m_colors[178] = new my_color_alpha( 64,192,128,   0);
  m_colors[179] = new my_color_alpha( 96,192,128,   0);
  m_colors[180] = new my_color_alpha(128,192,128,   0);
  m_colors[181] = new my_color_alpha(160,192,128,   0);
  m_colors[182] = new my_color_alpha(192,192,128,   0);
  m_colors[183] = new my_color_alpha(224,192,128,   0);
  m_colors[184] = new my_color_alpha(  0,224,128,   0);
  m_colors[185] = new my_color_alpha( 32,224,128,   0);
  m_colors[186] = new my_color_alpha( 64,224,128,   0);
  m_colors[187] = new my_color_alpha( 96,224,128,   0);
  m_colors[188] = new my_color_alpha(128,224,128,   0);
  m_colors[189] = new my_color_alpha(160,224,128,   0);
  m_colors[190] = new my_color_alpha(192,224,128,   0);
  m_colors[191] = new my_color_alpha(224,224,128,   0);
  m_colors[192] = new my_color_alpha(  0,  0,192,   0);
  m_colors[193] = new my_color_alpha( 32,  0,192,   0);
  m_colors[194] = new my_color_alpha( 64,  0,192,   0);
  m_colors[195] = new my_color_alpha( 96,  0,192,   0);
  m_colors[196] = new my_color_alpha(128,  0,192,   0);
  m_colors[197] = new my_color_alpha(160,  0,192,   0);
  m_colors[198] = new my_color_alpha(192,  0,192,   0);
  m_colors[199] = new my_color_alpha(224,  0,192,   0);
  m_colors[200] = new my_color_alpha(  0, 32,192,   0);
  m_colors[201] = new my_color_alpha( 32, 32,192,   0);
  m_colors[202] = new my_color_alpha( 64, 32,192,   0);
  m_colors[203] = new my_color_alpha( 96, 32,192,   0);
  m_colors[204] = new my_color_alpha(128, 32,192,   0);
  m_colors[205] = new my_color_alpha(160, 32,192,   0);
  m_colors[206] = new my_color_alpha(192, 32,192,   0);
  m_colors[207] = new my_color_alpha(224, 32,192,   0);
  m_colors[208] = new my_color_alpha(  0, 64,192,   0);
  m_colors[209] = new my_color_alpha( 32, 64,192,   0);
  m_colors[210] = new my_color_alpha( 64, 64,192,   0);
  m_colors[211] = new my_color_alpha( 96, 64,192,   0);
  m_colors[212] = new my_color_alpha(128, 64,192,   0);
  m_colors[213] = new my_color_alpha(160, 64,192,   0);
  m_colors[214] = new my_color_alpha(192, 64,192,   0);
  m_colors[215] = new my_color_alpha(224, 64,192,   0);
  m_colors[216] = new my_color_alpha(  0, 96,192,   0);
  m_colors[217] = new my_color_alpha( 32, 96,192,   0);
  m_colors[218] = new my_color_alpha( 64, 96,192,   0);
  m_colors[219] = new my_color_alpha( 96, 96,192,   0);
  m_colors[220] = new my_color_alpha(128, 96,192,   0);
  m_colors[221] = new my_color_alpha(160, 96,192,   0);
  m_colors[222] = new my_color_alpha(192, 96,192,   0);
  m_colors[223] = new my_color_alpha(224, 96,192,   0);
  m_colors[224] = new my_color_alpha(  0,128,192,   0);
  m_colors[225] = new my_color_alpha( 32,128,192,   0);
  m_colors[226] = new my_color_alpha( 64,128,192,   0);
  m_colors[227] = new my_color_alpha( 96,128,192,   0);
  m_colors[228] = new my_color_alpha(128,128,192,   0);
  m_colors[229] = new my_color_alpha(160,128,192,   0);
  m_colors[230] = new my_color_alpha(192,128,192,   0);
  m_colors[231] = new my_color_alpha(224,128,192,   0);
  m_colors[232] = new my_color_alpha(  0,160,192,   0);
  m_colors[233] = new my_color_alpha( 32,160,192,   0);
  m_colors[234] = new my_color_alpha( 64,160,192,   0);
  m_colors[235] = new my_color_alpha( 96,160,192,   0);
  m_colors[236] = new my_color_alpha(128,160,192,   0);
  m_colors[237] = new my_color_alpha(160,160,192,   0);
  m_colors[238] = new my_color_alpha(192,160,192,   0);
  m_colors[239] = new my_color_alpha(224,160,192,   0);
  m_colors[240] = new my_color_alpha(  0,192,192,   0);
  m_colors[241] = new my_color_alpha( 32,192,192,   0);
  m_colors[242] = new my_color_alpha( 64,192,192,   0);
  m_colors[243] = new my_color_alpha( 96,192,192,   0);
  m_colors[244] = new my_color_alpha(128,192,192,   0);
  m_colors[245] = new my_color_alpha(160,192,192,   0);
  m_colors[246] = new my_color_alpha(255,251,240,   0);
  m_colors[247] = new my_color_alpha(160,160,164,   0);
  m_colors[248] = new my_color_alpha(128,128,128,   0);
  m_colors[249] = new my_color_alpha(255,  0,  0,   0);
  m_colors[250] = new my_color_alpha(  0,255,  0,   0);
  m_colors[251] = new my_color_alpha(255,255,  0,   0);
  m_colors[252] = new my_color_alpha(  0,  0,255,   0);
  m_colors[253] = new my_color_alpha(255,  0,255,   0);
  m_colors[254] = new my_color_alpha(  0,255,255,   0);
  m_colors[255] = new my_color_alpha(255,255,255,   0);

  std::ofstream l_palette_file;
  l_palette_file.open("color_rom.coe");
  if(l_palette_file == NULL)
    {
      std::cout << "Error unabled to open palette file " << std::endl ;
      exit(-1);
    }

  l_palette_file << "memory_initialization_radix=16;" << std::endl ;
  l_palette_file << "memory_initialization_vector= " << std::endl ;

  for(uint32_t l_index = 0 ; l_index < 256 ; ++l_index)
    {
      uint32_t l_reduced_red = m_colors[l_index]->get_red() >> 2 ;
      uint32_t l_reduced_green = m_colors[l_index]->get_green() >> 2 ;
      uint32_t l_reduced_blue = m_colors[l_index]->get_blue() >> 2 ;
      uint32_t l_code = (l_reduced_red << 12) + (l_reduced_green << 6) + l_reduced_blue;
      l_palette_file << std::hex << l_code << (l_index != 255 ? "," : ";")<< std::dec << std::endl ;
    }
  l_palette_file.close();
}
