import {
    Box,
    Button,
    ButtonGroup,
    Flex,
    HStack,
    IconButton,
    Input,
    Text,
    SkeletonText,
    position,
  } from '@chakra-ui/react'
  import { FaLocationArrow, FaTimes } from 'react-icons/fa'
  
  import { useJsApiLoader,GoogleMap, Autocomplete, DirectionsRenderer } from '@react-google-maps/api'
  import { useState } from 'react'
  
  import { useRef } from 'react';
  
  
  // Center of the map (Goldsmiths University)
  const center = {lat: 51.47442, lng: -0.03541}
  
  //WESTMINSTER
  
  //Violence (RED)
  const WhitehallCt = {lat: 51.50602 , lng:-0.12462, radius:30}
  const ParliamentSt = {lat: 51.50062, lng:-0.12615, radius:50}
  const WestminsterPier = {lat: 51.50185, lng:-0.12400, radius:50}
  const WestminsterArms = {lat: 51.50062, lng: -0.12980, radius:20}
  const CarteretSt = {lat: 51.49973, lng: -0.13271, radius:15}
  const DacreSt = {lat: 51.49890, lng: -0.13264, radius:15}
  const StarbucksCoffee = {lat: 51.49908, lng: -0.13550, radius:15}
  const VictoriaSt = {lat: 51.49754, lng: -0.13538, radius:10}
  const OldPyeSt = {lat: 51.49754, lng: -0.13222, radius:40}
  const StMatthewStreet = {lat: 51.497102, lng: -0.133238, radius:10}
  const GreycoatPlace = {lat: 51.496519, lng: -0.133701, radius:10}
  const GreatPeterStreet = {lat: 51.496876, lng:-0.130487, radius:50}
  const DeanTrenchSt = {lat: 51.495912, lng: -0.128100 , radius:10}
  const HorseferryRd = {lat: 51.494828, lng: -0.129069 , radius:20}
  const ArnewaySt = {lat: 51.495378, lng: -0.131864, radius:20}
  const ChadwichSt = {lat: 51.496322, lng: -0.131978, radius:20}
  const ThorneySt = {lat: 51.493969, lng: -0.126162, radius:10}
  const PageSt = {lat: 51.493938, lng: -0.129264, radius:20}
  const RegencySt = {lat: 51.494229, lng: -0.132351, radius:20}
  const VincentStreet = {lat: 51.492524, lng: -0.131342, radius:20}
  const RegencyStreet = {lat: 51.492406, lng: -0.132277, radius:10}
  const WalcottSt = {lat: 51.493295, lng: -0.137398, radius:10}
  const VauxhallBridgeRoad = {lat: 51.492621, lng: -0.137603, radius:10}
  const HatherleyStreet = {lat: 51.492692, lng: -0.137361, radius:10}
  const HerrickSt = {lat: 51.491102, lng: -0.129670, radius:25}
  const CuretonSt = {lat: 51.490623, lng: -0.130482, radius:15}
  const AtterburySt = {lat:51.490485, lng: -0.127659, radius:15}
  const VictoriaStreet = {lat: 51.496596, lng: -0.142520, radius:50}
  const ThirlebyRoad = {lat: 51.496158, lng: -0.138331, radius:20}
  const GreencoatRow = {lat: 51.495541, lng: -0.136404, radius:10}
  const FrancisSt = {lat: 51.495182, lng: -0.138114, radius:15}
  const MorpethTerrace = {lat:51.495287,lng:-0.139967, radius:10}
  const StillingtonStreet = {lat: 51.494323, lng: -0.137402, radius:10}
  const SpenserStreet = {lat: 51.497474, lng: -0.137060, radius:15}
  const VandonStreet = {lat: 51.498760, lng: -0.136475, radius:10}
  const BuckinghamGate = {lat: 51.499252, lng: -0.138648, radius:10}
  const PalaceStreet = {lat: 51.499008, lng: -0.142333, radius:20}
  
  //Theft (Lime)
  const ScotlandYard = {lat: 51.50612 , lng:-0.12565, radius:30 }
  const KoreanCC = {lat: 51.50697,lng: -0.12499, radius:20}
  const CraigCt = {lat: 51.50671, lng: -0.12704, radius:50}
  const QueenElizabethCentre = {lat: 51.50053, lng:-0.12907, radius:40}
  const MargaretChurch = {lat: 51.50012, lng:-0.12626, radius:40}
  const TescoExpress = {lat: 51.50132, lng:-0.12484, radius:60}
  const GeorgeStreet = {lat: 51.50114, lng:-0.12804, radius:30}
  const OldQueenSt = {lat: 51.50078, lng:-0.13049, radius:30}
  const Broadway = {lat: 51.49967, lng:-0.13306, radius:10}
  const TheSanctuary = {lat: 51.49941, lng:-0.12937, radius:10}
  const PalmerSt = {lat: 51.49794, lng: -0.13540, radius:10}
  const B323St = {lat: 51.49764, lng: -0.13571, radius:10}
  const StMatthewSt = {lat: 51.4975, lng: -0.1333, radius:40}
  const RochesterRow = {lat: 51.496308,lng: -0.134781, radius:10}
  const GreatSmithSt = {lat: 51.498083,lng: -0.129897, radius:10}
  const GreatPeterSt = {lat: 51.496965,lng: -0.125598, radius:15}
  const TuftonSt = {lat: 51.496588,lng: -0.128445, radius:15}
  const BennettYard = {lat: 51.496046, lng: -0.128528, radius:18}
  const SmithSquare = {lat: 51.495759, lng: -0.126720, radius:10}
  const RomneySt = {lat: 51.495309, lng: -0.128019, radius:10}
  const HorseferryRoad = {lat: 51.494866, lng: -0.129485, radius:20}
  const MedwaySt = {lat: 51.495421, lng: -0.130969, radius:25}
  const ChadwichStreet = {lat: 51.496606, lng: -0.132080, radius:25}
  const PageStreet = {lat: 51.493996, lng:-0.126793, radius:40}
  const MaunselSt = {lat: 51.494517, lng: -0.132976, radius:20}
  const RochesterSt = {lat: 51.495079, lng: -0.134605, radius:10}
  const VincentSt = {lat: 51.492958, lng: -0.131147, radius:30}
  const HatherleySt = {lat: 51.492964, lng: -0.137797, radius:10}
  const DouglasStreet = {lat: 51.491329, lng: -0.133512, radius:10}
  const Millbank = {lat:51.491832, lng: -0.125412, radius:20};
  const BessboroughGardens = {lat: 51.488892, lng: -0.129819, radius:30};
  const VictoriaSquare = {lat: 51.497790, lng: -0.144900, radius:20};
  const LowerGrosvenorPlace = {lat: 51.496846, lng: -0.141836, radius:45}
  const KingsScholarsPassage = {lat: 51.495889, lng:-0.141602, radius:30}
  const AshleyPl = {lat: 51.496255, lng: -0.140257, radius:20}
  const AmbrosdenAvenue = {lat: 51.496387, lng: -0.139407, radius:10}
  const thirlebyrd = {lat: 51.496364, lng: -0.138538, radius:10}
  const howichplace = {lat: 51.496783, lng: -0.136799, radius:90}
  const ArtilleryRow = {lat: 51.496422, lng: -0.135673, radius:30}
  const FrancisStreet = {lat: 51.495283, lng: -0.138347, radius:20}
  const SpenserSt = {lat: 51.497923, lng: -0.136431, radius:30}
  const VandonSt = {lat: 51.498753, lng: -0.136759, radius:20}
  const QueenAnneGate = {lat: 51.500546, lng: -0.133356, radius:10}
  const PalaceSt = {lat: 51.499074, lng: -0.142662, radius:20}
  const Warwichrow = {lat: 51.498402, lng: -0.142873, radius:30}
  const StaffordPlace = {lat: 51.499522, lng: -0.141418, radius:40}
  const YeomanRow = {lat: 51.497041, lng: -0.166462, radius:10}
  
  //Robbery/Burglary/Shoplifting (Orange/Amber)
  const HorseGuardsAve  ={lat:51.50500, lng: -0.12481, radius: 50}
  const MatthewParkerSt = {lat:51.50032, lng:-0.13034, radius:20}
  const CaxtonSt = {lat: 51.49843, lng: -0.13591, radius:15}
  const B323 = {lat: 51.49736, lng: -0.13567, radius:10}
  const SaintMatthewSt = {lat: 51.496899,lng: -0.133187, radius:10}
  const MonckStreet = {lat: 51.495408, lng: -0.130747, radius:15}
  const HidePlace = {lat: 51.492091, lng: -0.133685, radius:15}
  const WillowPlace = {lat: 51.493132, lng: -0.137973, radius:10}
  const DouglasSt = {lat: 51.491377, lng: -0.133639, radius:30}
  const BeestonPlace = {lat: 51.497926, lng:-0.145605, radius:20}
  const VictoriaSqr = {lat: 51.497987,lng: - 0.144777, radius:20}
  const AllingtonSt = {lat: 51.496806, lng: -0.142958, radius:10}
  const VauxhallBridgeRd = {lat: 51.496271, lng: -0.142462, radius:25}
  const AmbrosdenAve = {lat: 51.496349, lng: -0.139490, radius:10}
  const HowichPlace = {lat:51.496689, lng: -0.137099, radius:100}
  const StillingtonSt = {lat: 51.494555, lng: -0.138282, radius:10}
  const CardinalWalk = {lat: 51.498009, lng: -0.140239, radius:30}
  const WarwichRow = {lat: 51.498428, lng:-0.142855, radius:15}
  
  //Vehicle crime (Purple)
  const DacreSreet = {lat: 51.49894, lng: -0.13287, radius:10}
  const MonckSt = {lat: 51.496294, lng: -0.130817, radius:20}
  const RutherfordSt = {lat: 51.494081, lng:-0.132844, radius:20}
  const EsterbrookeSt = {lat: 51.491998, lng: -0.132809, radius:20}
  const PonsonbyPlace = {lat: 51.490199, lng: -0.130802, radius:20}
  const ThirlebyRd = {lat: 51.496344, lng: -0.138701, radius:10}
  const HowichPl = {lat: 51.496677, lng: -0.137328, radius:30}
  
  //Scams (Yellow)
  const WestminsterBridge = {lat: 51.500871, lng: -0.122025, radius:100}
  
  // Chelsea
  
  //Violence (RED)
  const OvingtonMews = {lat: 51.497801, lng: -0.165987, radius:10}
  const EgertonGardensMews = {lat: 51.496971, lng: -0.167552, radius:10}
  const HaskerStreet = {lat: 51.494559, lng: -0.164822, radius:10}
  const CadoganGate = {lat: 51.494537, lng: -0.158688, radius:10}
  const RawlingsSt = {lat: 51.493170, lng: -0.163328, radius:20}
  const DraycottAve = {lat: 51.492443, lng: -0.164563, radius:15}
  const MakinsSt = {lat: 51.492144, lng: -0.166630, radius:15}
  const IxworthPlace = {lat:51.491883, lng: -0.168751, radius:10}
  const BuryWalk = {lat: 51.491314, lng: -0.171191, radius:20}
  const DanuseSt = {lat: 51.490201, lng: -0.167067, radius:10}
  const CaleSt = {lat: 51.490142, lng: -0.170399, radius:10}
  const FloodWalk = {lat: 51.486593, lng: -0.166984, radius:25}
  const roalhospitalroad = {lat: 51.484959, lng: -0.162886, radius:10}
  const PetytPlace = {lat: 51.483023, lng: -0.171458, radius:10}
  const DanversSt = {lat: 51.482906, lng: -0.172499, radius:10}
  const CarlyleSquare = {lat: 51.486648, lng: -0.172969, radius:10}
  const ElmParkGardens = {lat: 51.487232, lng: -0.177330, radius:10}
  const kingsrd = {lat: 51.485102, lng: -0.174481, radius:10}
  const PeonyCourt = {lat: 51.486211, lng: -0.179851, radius:15}
  const ChelseaParkGardens = {lat: 51.485217, lng: -0.177765, radius:10}
  const BeaufordStreet = {lat: 51.484544, lng: -0.175621, radius:10}
  const lamontroadpassage = {lat: 51.483899, lng: -0.176918, radius:10}
  const LimerstonStreet = {lat: 51.484386, lng: -0.179350, radius:10}
  const NightingalePl = {lat: 51.484519, lng: -0.180736, radius:10}
  const LangtonSt = {lat: 51.482440, lng: -0.180627, radius:10}
  const RileySt = {lat: 51.481952, lng: -0.176829, radius:10}
  const AnnLane = {lat: 51.482614, lng: -0.177716, radius:15}
  const EdithGroveCarPark = {lat: 51.480378, lng: -0.179936, radius:10}
  const ChelseaTheatre = {lat: 51.48165,lng: -0.17977, radius:20}
  const edithgrove = {lat: 51.481790, lng: -0.181630, radius:10}
  const lotsrd = {lat: 51.480159, lng: -0.185582, radius:10}
  const ThorndickCl = {lat: 51.480502, lng: -0.184263, radius:15}
  const fullhamroad = {lat: 51.483044, lng: -0.185802, radius:15}
  
  //Theft (Lime)
  const EgertonTerrace = {lat: 51.497004, lng:-0.168021, radius:10}
  const FirstSt = {lat: 51.495003, lng: -0.165864, radius:15}
  const CrescentPl = {lat: 51.494492, lng: -0.168298, radius:20}
  const ClabonMews = {lat: 51.495061, lng: -0.161870, radius:10}
  const PavilionRd = {lat: 51.494333, lng: -0.159004, radius:10}
  const CadoganStreet = {lat: 51.493372, lng: -0.161631, radius:10}
  const DraycottTerrace = {lat: 51.492616, lng: -0.160657, radius:10}
  const culfordgardens = {lat: 51.491954, lng: -0.160568, radius:15}
  const SymonsSt = {lat: 51.492464, lng: -0.159449, radius:25}
  const A3216 = {lat: 51.492721, lng: -0.156835, radius:15}
  const SaatchiGallery = {lat: 51.491039, lng: -0.158560, radius:40}
  const parkingarea = {lat: 51.490514, lng: -0.161048, radius:20}
  const MarkhamSquare = {lat: 51.490054, lng: -0.164922, radius:10}
  const CaleStreet = {lat: 51.490092, lng: -0.170533, radius:15}
  const wellingtonsquare = {lat: 51.489579, lng: -0.163216, radius:10}
  const ManresaRd = {lat: 51.487463, lng: -0.171406, radius:10}
  const KingsRd = {lat: 51.487370, lng: -0.168958, radius:25}
  const OakleyGardens = {lat: 51.485388, lng: -0.167115, radius:10}
  const StLooAve = {lat: 51.485087, lng: -0.164984, radius:10}
  const eastroad = {lat: 51.488180, lng: -0.156784, radius:10}
  const ElmParkRd = {lat: 51.486212, lng: -0.177255, radius:10}
  const MulberryWalk = {lat: 51.486004, lng: -0.175742, radius:10}
  const ParkWalk = {lat: 51.486045, lng: -0.180261, radius:10}
  const beaufortst = {lat: 51.484708, lng: -0.175972, radius:10}
  const MoravianPl = {lat: 51.482578, lng: -0.175882, radius:10}
  const annlane = {lat: 51.482541, lng: -0.177908, radius:10}
  const EdithYard = {lat: 51.481527, lng: -0.180572, radius:10}
  const AshburnhamRoad = {lat: 51.479920, lng: -0.181066, radius:10}
  const thorndickcl = {lat: 51.480531, lng: -0.184145, radius:10}
  const FullhamRoad = {lat: 51.48274, lng: -0.18615, radius:30}
  
  //Robbery/Burglary/Shoplifting (Orange/Amber)
  const BeauchampPlace = {lat: 51.497393, lng: -0.164317, radius:10}
  const WaltonStreet = {lat: 51.495586, lng: -0.165685, radius:15}
  const MilnerSt = {lat: 51.494328, lng: -0.163893, radius:10}
  const PavilionSt = {lat: 51.496797, lng: -0.159499, radius:10}
  const CadoganSt = {lat: 51.493447, lng: -0.161218, radius:10}
  const SloaneAvenue = {lat: 51.491994, lng: -0.164937, radius:10}
  const burywalk = {lat: 51.491378, lng: -0.171252, radius:10}
  const LincolnSt = {lat:51.491321, lng: -0.161242, radius:10}
  const CulfordGardens = {lat: 51.491843, lng: -0.160803, radius:15}
  const SymonsStreet = {lat: 51.492524, lng: -0.159197, radius:20}
  const ParkingArea = {lat: 51.490471, lng: -0.161031, radius:30}
  const CoulsonSt = {lat: 51.490956, lng: -0.162167, radius:10}
  const BywaterSt = {lat: 51.490092, lng: -0.163832, radius:10}
  const DanuseStreet = {lat: 51.490140, lng: -0.167058, radius:10}
  const SParade = {lat: 51.489183, lng: -0.174755, radius:10}
  const DovehouseSt = {lat: 51.488955, lng: -0.171503, radius:10}
  const TheTrafalgar = {lat: 51.48857, lng:-0.16701, radius:30}
  const MarksAndSpencer = {lat: 51.48895,lng: -0.16470, radius:20}
  const WoodfallSt = {lat: 51.488513, lng: -0.162567, radius:10}
  const StLeonardsTerrace = {lat: 51.488754, lng: -0.160931, radius:10}
  const ChelseaManorGardens = {lat: 51.486613, lng: -0.168426, radius:10}
  const CheyneWalk = {lat: 51.483683, lng: -0.166591, radius:10}
  const EastRoad = {lat: 51.488214, lng: -0.156857, radius:10}
  const PaultonsSquare = {lat: 51.484193, lng: -0.173104, radius:10}
  const MallordSt = {lat: 51.485938, lng: -0.174194, radius:10}
  const KingsRoad = {lat: 51.485058, lng: -0.174578, radius:15}
  const FullhamRd = {lat: 51.486342, lng: -0.180217, radius:10}
  const WintertonPlace = {lat: 51.485352, lng: -0.180164, radius:10}
  const SlaidburnSt = {lat: 51.482390, lng: -0.181394, radius:10}
  const BlantyreStreet = {lat: 51.481524, lng: -0.178327, radius:10}
  const EdithGrove = {lat: 51.481945, lng: -0.181802, radius:10}
  const upcernerd = {lat: 51.479163, lng: -0.183178, radius:10}
  const hortensiaroad = {lat: 51.482588, lng: -0.186166, radius:20}
  //Vehicle crime (Purple)
  const BeauchampPl = {lat: 51.496964, lng: -0.163356, radius:10}
  const EgertonGardens = {lat: 51.496778, lng: -0.167996, radius:10}
  const EgertonGardens_two = {lat: 51.495638, lng: -0.168404, radius:10}
  const OvingstonStreet = {lat: 51.495813, lng: -0.165249, radius:15}
  const CrescentPlace = {lat: 51.494493, lng: -0.168153, radius:10}
  const HalseySt = {lat: 51.494375, lng: -0.163276, radius:10}
  const MilnerStreet = {lat: 51.494884, lng: -0.161753, radius:20}
  const ShafloMews = {lat: 51.496332, lng: -0.161021, radius:10}
  const CadoganGardens = {lat: 51.492660, lng: -0.160315, radius:10}
  const DraycottAvenue = {lat: 51.492478, lng: -0.164651, radius:10}
  const SloaneAve = {lat: 51.491833, lng: -0.164570, radius:15}
  const SprimontPl = {lat: 51.490914, lng: -0.164573, radius:10}
  const JubileePl = {lat: 51.489498, lng: -0.166167, radius:10}
  const WellingtonSquare = {lat: 51.489547, lng: -0.163095, radius:10}
  const DovehouseStreet = {lat: 51.488786, lng: -0.171348, radius:10}
  const stleonardsterrace = {lat: 51.488812, lng: -0.160852, radius:10}
  const ManresaRoad = {lat: 51.487419, lng: -0.171367, radius:10}
  const CheyneGardens = {lat: 51.484388, lng: -0.165688, radius:10}
  const RoyalHospitalRoad = {lat: 51.484895, lng: -0.162965, radius:10}
  const ParadiseWalk = {lat: 51.485147, lng: -0.160781, radius:10}
  const FranklinsRow = {lat: 51.489218, lng: -0.158497, radius:10}
  const SloaneCourtWest = {lat: 51.489998, lng: -0.157125, radius:10}
  const LordshipPl = {lat: 51.483620, lng: -0.169996, radius:10}
  const OldChurchStreet = {lat: 51.486598, lng: -0.173539, radius:10}
  const elmparkgarndens = {lat: 51.487124, lng: -0.177274, radius:10}
  const kingsroad = {lat: 51.485030, lng: -0.174527, radius:10}
  const parkwalk = {lat: 51.484913, lng: -0.178669, radius:10}
  const BeaufortSt = {lat: 51.484555, lng: -0.175819, radius:15}
  const LamontRoadPassage = {lat: 51.483840, lng: -0.177209, radius:10}
  const limerstonstreet = {lat: 51.484193, lng: -0.179150, radius:10}
  const GertrudeStreet = {lat: 51.483486, lng: -0.180667, radius:10}
  const LamontRoad = {lat: 51.482759, lng: -0.179820, radius:10}
  const LangtonStreet = {lat: 51.482484, lng: -0.180696, radius:15}
  const TademaRoad = {lat: 51.479843, lng: -0.182148, radius:10}
  const UpcerneRd = {lat: 51.478897, lng: -0.182988, radius:10}
  const LotsRd = {lat: 51.479102, lng: -0.184726, radius:10}
  const HortensiaRd = {lat: 51.481244, lng: -0.184550, radius:10}
  
  //Scams (Yellow)
  const DaycottsApartments = {lat:51.491657, lng: -0.162303, radius:10}
  const IvyChelseaGarden = {lat:51.48707, lng: -0.16938, radius:10}
  const sloaneave = {lat: 51.49240, lng: -0.16571, radius:20}
  const RoyalHospitalRd = {lat: 51.486650, lng: -0.160469, radius:15}
  
  // Kensington
  
  //Violence (RED)
  const FawcettStreet = {lat: 51.484400, lng: -0.186457, radius: 15}
  const HollywoodRoad = {lat: 51.486420, lng: -0.184882, radius:10}
  const HarleyGardens = {lat: 51.487542, lng: -0.181124, radius: 10}
  const IfieldRoad = {lat: 51.485139, lng: -0.188766, radius: 10}
  const RedcliffeStreet = {lat: 51.485971, lng:-0.188831, radius: 10}
  const TregunterRoad = {lat: 51.486095, lng: -0.187087, radius:10}
  //Theft (Lime)
  const BillingStreet = {lat: 51.481426, lng: -0.188540, radius: 10}
  const NevilleStreet = {lat: 51.490303, lng: -0.175734, radius:10}
  const cathcartRd = {lat:51.484942, lng: -0.187267, radius: 10}
  //Robbery/Burglary/Shoplifting (Orange/Amber)
  const FinboroughRd = {lat: 51.483946, lng: -0.186021, radius: 10}
  const fawcettstreet = {lat: 51.485051, lng: -0.185503, radius: 10}
  const SeymourWalk = {lat: 51.486338,lng:-0.183079, radius: 10}
  const EvelynGardens = {lat: 51.488599, lng:-0.179409, radius:10}
  const CathcartRoad = {lat: 51.484990, lng: -0.187350, radius:10}
  const tregunterRd = {lat: 51.486164, lng: -0.186946, radius:10}
  //Vehicle crime (Purple)
  const FinboroughRoad = {lat: 51.483895, lng: -0.185975, radius:15}
  const fawcettSt = {lat: 51.484497, lng: -0.186574, radius: 10}
  const seymourwalk = {lat: 51.486263, lng: -0.182945, radius: 10}
  const RedcliffeRoad = {lat: 51.486986, lng: -0.182945, radius: 10}
  const GilstonRoad = {lat: 51.487685, lng: -0.182268, radius: 10}
  //Scams (Yellow)
  
  
  function Apptwo() {
  const {isLoaded} = useJsApiLoader({
    googleMapsApiKey: process.env.REACT_APP_GOOGLE_MAPS_API_KEY,
    libraries: ['places', 'geometry'],
    })
  
    const [map, setMap] = useState (/** @type google.maps.Map */(null))
    const [directionsResponse, setDirectionResponse] = useState(null)
    const [distance, setDistance] = useState('')
    const [duration, setDuration] = useState('')
  
    const originRef = useRef()
  
    const destionationRef = useRef()
  
  /* global google */
  
    
  
  
  
    if(!isLoaded) {
      return <SkeletonText />
    }
  
    // HOW TO DO BUS ROUTES
        /* eslint-disable-next-line no-undef */
        // travelMode: google.maps.TransitMode.BUS,
        /* eslint-disable-next-line no-undef */
        // travelMode: google.maps.TravelMode.TRANSIT
    
    async function calculateRoute() {
      const selectTravelMode = document.getElementById('travels').value;
      if (originRef.current.value === '' || destionationRef.current.value === '') {
        return
      }
      /* eslint-disable-next-line no-undef */
      const directionsService = new google.maps.DirectionsService()
   
      const results = await directionsService.route ({
        
        origin: originRef.current.value,
        destination: destionationRef.current.value,
        /* eslint-disable-next-line no-undef */
        travelMode: getGoogleMapsTravelMode(selectTravelMode)
  
      });
    
      //check if route enters any circles
      const routeCoordinates = results.routes[0].overview_path;
    
      //Locations
      //Violence 
      const ViolenceLocations = {WhitehallCt: {lat: WhitehallCt.lat,lng: WhitehallCt.lng, radius: WhitehallCt.radius},
      WestminsterPier: {lat: WestminsterPier.lat, lng: WestminsterPier.lng, radius: WestminsterPier.radius},
      WestminsterArms: {lat: WestminsterArms.lat, lng: WestminsterArms.lng, radius: WestminsterArms.radius},
      CarteretSt: {lat: CarteretSt.lat, lng: CarteretSt.lng, radius: CarteretSt.radius},
      DacreSt: {lat: DacreSt.lat,lng: DacreSt.lng, radius: DacreSt.radius},
      StarbucksCoffee: {lat: StarbucksCoffee.lat, lng: StarbucksCoffee.lng,radius:StarbucksCoffee.radius},
      VictoriaSt: {lat: VictoriaSt.lat, lng: VictoriaSt.lng,radius:VictoriaSt.radius},
      OldPyeSt: {lat: OldPyeSt.lat, lng: OldPyeSt.lng,radius:OldPyeSt.radius},
      StMatthewStreet: {lat: StMatthewStreet.lat, lng: StMatthewStreet.lng,radius:StMatthewStreet.radius},
      GreycoatPlace: {lat: GreycoatPlace.lat, lng: GreycoatPlace.lng,radius:GreycoatPlace.radius},
      GreatPeterStreet: {lat: GreatPeterStreet.lat, lng: GreatPeterStreet.lng,radius:GreatPeterStreet.radius},
      DeanTrenchSt: {lat: DeanTrenchSt.lat, lng: DeanTrenchSt.lng,radius:DeanTrenchSt.radius},
      HorseferryRd: {lat: HorseferryRd.lat, lng: HorseferryRd.lng,radius:HorseferryRd.radius},
      ArnewaySt: {lat: ArnewaySt.lat, lng: ArnewaySt.lng,radius:ArnewaySt.radius},
      ChadwichSt: {lat: ChadwichSt.lat, lng: ChadwichSt.lng,radius:ChadwichSt.radius},
      ThorneySt: {lat: ThorneySt.lat, lng: ThorneySt.lng,radius:ThorneySt.radius},
      PageSt: {lat: PageSt.lat, lng: PageSt.lng,radius:PageSt.radius},
      RegencySt: {lat: RegencySt.lat, lng: RegencySt.lng,radius:RegencySt.radius},
      VincentStreet: {lat: VincentStreet.lat, lng: VincentStreet.lng,radius:VincentStreet.radius},
      RegencyStreet: {lat: RegencyStreet.lat, lng: RegencyStreet.lng,radius:RegencyStreet.radius},
      WalcottSt: {lat: WalcottSt.lat, lng: WalcottSt.lng,radius:WalcottSt.radius},
      VauxhallBridgeRoad: {lat: VauxhallBridgeRoad.lat, lng: VauxhallBridgeRoad.lng,radius:VauxhallBridgeRoad.radius},
      HatherleyStreet: {lat: HatherleyStreet.lat, lng: HatherleyStreet.lng,radius:HatherleyStreet.radius},
      HerrickSt: {lat: HerrickSt.lat, lng: HerrickSt.lng,radius:HerrickSt.radius},
      CuretonSt: {lat: CuretonSt.lat, lng: CuretonSt.lng,radius:CuretonSt.radius},
      AtterburySt: {lat: AtterburySt.lat, lng: AtterburySt.lng,radius:AtterburySt.radius},
      VictoriaStreet: {lat: VictoriaStreet.lat, lng: VictoriaStreet.lng,radius:VictoriaStreet.radius}, 
      ThirlebyRoad: {lat: ThirlebyRoad.lat, lng: ThirlebyRoad.lng,radius:ThirlebyRoad.radius},
      GreencoatRow: {lat: GreencoatRow.lat, lng: GreencoatRow.lng,radius:GreencoatRow.radius},
      FrancisSt: {lat: FrancisSt.lat, lng: FrancisSt.lng,radius:FrancisSt.radius},
      MorpethTerrace: {lat: MorpethTerrace.lat, lng: MorpethTerrace.lng,radius:MorpethTerrace.radius},
      StillingtonStreet: {lat: StillingtonStreet.lat, lng: StillingtonStreet.lng,radius:StillingtonStreet.radius},
      SpenserStreet: {lat: SpenserStreet.lat, lng: SpenserStreet.lng,radius:SpenserStreet.radius},
      VandonStreet: {lat: VandonStreet.lat, lng: VandonStreet.lng,radius:VandonStreet.radius},
      BuckinghamGate: {lat: BuckinghamGate.lat, lng: BuckinghamGate.lng,radius:BuckinghamGate.radius},
      PalaceStreet: {lat: PalaceStreet.lat, lng: PalaceStreet.lng,radius:PalaceStreet.radius},
      ParliamentSt: {lat: ParliamentSt.lat, lng: ParliamentSt.lng,radius:ParliamentSt.radius},
      OvingtonMews: {lat: OvingtonMews.lat, lng: OvingtonMews.lng,radius:OvingtonMews.radius},
      EgertonGardensMews: {lat: EgertonGardensMews.lat, lng: EgertonGardensMews.lng,radius:EgertonGardensMews.radius},
      HaskerStreet: {lat: HaskerStreet.lat, lng: HaskerStreet.lng,radius:HaskerStreet.radius},
      CadoganGate: {lat: CadoganGate.lat, lng: CadoganGate.lng,radius:CadoganGate.radius},
      RawlingsSt: {lat: RawlingsSt.lat, lng: RawlingsSt.lng,radius:RawlingsSt.radius},
      DraycottAve: {lat: DraycottAve.lat, lng: DraycottAve.lng,radius:DraycottAve.radius},
      MakinsSt: {lat: MakinsSt.lat, lng: MakinsSt.lng,radius:MakinsSt.radius},
      IxworthPlace: {lat: IxworthPlace.lat, lng: IxworthPlace.lng,radius:IxworthPlace.radius},
      BuryWalk: {lat: BuryWalk.lat, lng: BuryWalk.lng,radius:BuryWalk.radius},
      DanuseSt: {lat: DanuseSt.lat, lng: DanuseSt.lng,radius:DanuseSt.radius},
      CaleSt: {lat: CaleSt.lat, lng: CaleSt.lng,radius:CaleSt.radius},
      FloodWalk: {lat: FloodWalk.lat, lng: FloodWalk.lng,radius:FloodWalk.radius},
      roalhospitalroad: {lat: roalhospitalroad.lat, lng: roalhospitalroad.lng,radius:roalhospitalroad.radius},
      PetytPlace: {lat: PetytPlace.lat, lng: PetytPlace.lng,radius:PetytPlace.radius},
      DanversSt: {lat: DanversSt.lat, lng: DanversSt.lng,radius:DanversSt.radius},
      CarlyleSquare: {lat: CarlyleSquare.lat, lng: CarlyleSquare.lng,radius:CarlyleSquare.radius},
      ElmParkGardens: {lat: ElmParkGardens.lat, lng: ElmParkGardens.lng,radius:ElmParkGardens.radius},
      kingsrd: {lat: kingsrd.lat, lng: kingsrd.lng,radius:kingsrd.radius},
      KingsRd: {lat: KingsRd.lat, lng: KingsRd.lng,radius:15},
      PeonyCourt: {lat: PeonyCourt.lat, lng: PeonyCourt.lng,radius:PeonyCourt.radius},
      ChelseaParkGardens: {lat: ChelseaParkGardens.lat, lng: ChelseaParkGardens.lng,radius:ChelseaParkGardens.radius},
      BeaufordStreet: {lat: BeaufordStreet.lat, lng: BeaufordStreet.lng,radius:BeaufordStreet.radius},
      lamontroadpassage: {lat: lamontroadpassage.lat, lng: lamontroadpassage.lng,radius:lamontroadpassage.radius},
      LimerstonStreet: {lat: LimerstonStreet.lat, lng: LimerstonStreet.lng,radius:LimerstonStreet.radius},
      NightingalePl: {lat: NightingalePl.lat, lng: NightingalePl.lng,radius: NightingalePl.radius},
      LangtonSt: {lat: LangtonSt.lat, lng: LangtonSt.lng,radius:LangtonSt.radius},
      RileySt: {lat: RileySt.lat, lng: RileySt.lng,radius:RileySt.radius},
      AnnLane: {lat: AnnLane.lat, lng: AnnLane.lng,radius:AnnLane.radius},
      EdithGroveCarPark: {lat: EdithGroveCarPark.lat, lng: EdithGroveCarPark.lng,radius:EdithGroveCarPark.radius},
      ChelseaTheatre: {lat: ChelseaTheatre.lat, lng: ChelseaTheatre.lng,radius:ChelseaTheatre.radius},
      edithgrove: {lat: edithgrove.lat, lng: edithgrove.lng,radius:edithgrove.radius},
      lotsrd: {lat: lotsrd.lat, lng: lotsrd.lng,radius:lotsrd.radius},
      ThorndickCl: {lat: ThorndickCl.lat, lng: ThorndickCl.lng,radius:ThorndickCl.radius},
      fullhamroad: {lat: fullhamroad.lat, lng: fullhamroad.lng,radius:fullhamroad.radius},
      TheTrafalgar: {lat:TheTrafalgar.lat,lng: TheTrafalgar.lng,radius:15}
      }
  
      // Theft
      const TheftLocations = {ScotlandYard:{lat: ScotlandYard.lat,lng: ScotlandYard.lng, radius: ScotlandYard.radius},
        KoreanCC:{lat: KoreanCC.lat,lng: KoreanCC.lng, radius: KoreanCC.radius},
        CraigCt:{lat: CraigCt.lat,lng: CraigCt.lng, radius: CraigCt.radius},
        QueenElizabethCentre:{lat: QueenElizabethCentre.lat,lng: QueenElizabethCentre.lng, radius: QueenElizabethCentre.radius},
        MargaretChurch:{lat: MargaretChurch.lat,lng: MargaretChurch.lng, radius: MargaretChurch.radius},
        TescoExpress:{lat: TescoExpress.lat,lng: TescoExpress.lng, radius: TescoExpress.radius},
        GeorgeStreet:{lat: GeorgeStreet,lng: GeorgeStreet.lng, radius: GeorgeStreet.radius},
        OldQueenSt:{lat: OldQueenSt.lat,lng: OldQueenSt.lng, radius: OldQueenSt.radius},
        Broadway:{lat: Broadway.lat,lng: Broadway.lng, radius: Broadway.radius},
        TheSanctuary:{lat: TheSanctuary.lat,lng: TheSanctuary.lng, radius: TheSanctuary.radius},
        PalmerSt:{lat: PalmerSt.lat,lng: PalmerSt.lng, radius: PalmerSt.radius},
        B323St:{lat: B323St.lat,lng: B323St.lng, radius: B323St.radius},
        StMatthewSt:{lat: StMatthewSt.lat,lng: StMatthewSt.lng, radius: StMatthewSt.radius},
        RochesterRow:{lat: RochesterRow.lat,lng: RochesterRow.lng, radius: RochesterRow.radius},
        GreatSmithSt:{lat: GreatSmithSt.lat,lng: GreatSmithSt.lng, radius: GreatSmithSt.radius},
        GreatPeterSt:{lat: GreatPeterSt.lat,lng: GreatPeterSt.lng, radius: GreatPeterSt.radius},
        TuftonSt:{lat: TuftonSt.lat,lng: TuftonSt.lng, radius: TuftonSt.radius},
        BennettYard:{lat: BennettYard.lat,lng: BennettYard.lng, radius: BennettYard.radius},
        SmithSquare:{lat: SmithSquare.lat,lng: SmithSquare.lng, radius: SmithSquare.radius},
        RomneySt:{lat: RomneySt.lat,lng: RomneySt.lng, radius: RomneySt.radius},
        HorseferryRoad:{lat: HorseferryRoad.lat,lng: HorseferryRoad.lng, radius: HorseferryRoad.radius},
        MedwaySt:{lat: MedwaySt.lat,lng: MedwaySt.lng, radius: MedwaySt.radius},
        ChadwichStreet:{lat: ChadwichStreet.lat,lng: ChadwichStreet.lng, radius: ChadwichStreet.radius},
        PageStreet:{lat: PageStreet.lat,lng: PageStreet.lng, radius: PageStreet.radius},
        MaunselSt:{lat: MaunselSt.lat,lng: MaunselSt.lng, radius: MaunselSt.radius},
        RochesterSt:{lat: RochesterSt.lat,lng: RochesterSt.lng, radius: RochesterSt.radius},
        VincentSt:{lat: VincentSt.lat,lng: VincentSt.lng, radius: VincentSt.radius},
        HatherleySt:{lat: HatherleySt.lat,lng: HatherleySt.lng, radius: HatherleySt.radius},
        DouglasStreet:{lat: DouglasStreet.lat,lng: DouglasStreet.lng, radius: DouglasStreet.radius},
        Millbank:{lat: Millbank.lat,lng: Millbank.lng, radius: Millbank.radius},
        BessboroughGardens:{lat: BessboroughGardens.lat,lng: BessboroughGardens.lng, radius: BessboroughGardens.radius},
        VictoriaSquare:{lat: VictoriaSquare.lat,lng: VictoriaSquare.lng, radius: VictoriaSquare.radius},
        LowerGrosvenorPlace:{lat: LowerGrosvenorPlace.lat,lng: LowerGrosvenorPlace.lng, radius: LowerGrosvenorPlace.radius},
        KingsScholarsPassage:{lat: KingsScholarsPassage.lat,lng: KingsScholarsPassage.lng, radius: KingsScholarsPassage.radius},
        AshleyPl:{lat: AshleyPl.lat,lng: AshleyPl.lng, radius: AshleyPl.radius},
        AmbrosdenAvenue:{lat: AmbrosdenAvenue.lat,lng: AmbrosdenAvenue.lng, radius: AmbrosdenAvenue.radius},
        thirlebyrd:{lat: thirlebyrd.lat,lng: thirlebyrd.lng, radius: thirlebyrd.radius},
        howichplace:{lat: howichplace.lat,lng: howichplace.lng, radius: howichplace.radius},
        ArtilleryRow:{lat: ArtilleryRow.lat,lng: ArtilleryRow.lng, radius: ArtilleryRow.radius},
        FrancisStreet:{lat: FrancisStreet.lat,lng: FrancisStreet.lng, radius: FrancisStreet.radius},
        SpenserSt:{lat: SpenserSt.lat,lng: SpenserSt.lng, radius: SpenserSt.radius},
        VandonSt:{lat: VandonSt.lat,lng: VandonSt.lat, radius: VandonSt.radius},
        QueenAnneGate:{lat: QueenAnneGate.lat,lng: QueenAnneGate.lng, radius: QueenAnneGate.radius},
        PalaceSt:{lat: PalaceSt.lat,lng: PalaceSt.lng, radius: PalaceSt.radius},
        Warwichrow:{lat: Warwichrow.lat,lng: Warwichrow.lng, radius: Warwichrow.radius},
        StaffordPlace:{lat: StaffordPlace.lat,lng: StaffordPlace.lng, radius: StaffordPlace.radius},
        YeomanRow:{lat: YeomanRow.lat,lng: YeomanRow.lng, radius: YeomanRow.radius},
        EgertonTerrace:{lat: EgertonTerrace.lat,lng: EgertonTerrace.lng, radius: EgertonTerrace.radius},
        FirstSt:{lat: FirstSt.lat,lng: FirstSt.lng, radius: FirstSt.radius},
        CrescentPl:{lat: CrescentPl.lat,lng: CrescentPl.lng, radius: CrescentPl.radius},
        ClabonMews:{lat: ClabonMews.lat,lng: ClabonMews.lng, radius: ClabonMews.radius},
        PavilionRd:{lat: PavilionRd.lat,lng: PavilionRd.lng, radius: PavilionRd.radius},
        CadoganStreet:{lat: CadoganStreet.lat,lng: CadoganStreet.lng, radius: CadoganStreet.radius},
        DraycottTerrace:{lat: DraycottTerrace.lat,lng: DraycottTerrace.lng, radius: DraycottTerrace.radius},
        culfordgardens:{lat: culfordgardens.lat,lng: culfordgardens.lng, radius: culfordgardens.radius},
        SymonsSt:{lat: SymonsSt.lat,lng: SymonsSt.lng, radius: SymonsSt.radius},
        A3216:{lat: A3216.lat,lng: A3216.lng, radius: A3216.radius},
        SaatchiGallery:{lat: SaatchiGallery.lat,lng: SaatchiGallery.lng, radius: SaatchiGallery.radius},
        parkingarea:{lat: parkingarea.lat,lng: parkingarea.lng, radius: parkingarea.radius},
        MarkhamSquare:{lat: MarkhamSquare.lat,lng: MarkhamSquare.lng, radius: MarkhamSquare.radius},
        CaleStreet:{lat: CaleStreet.lat,lng: CaleStreet.lng, radius: CaleStreet.radius},
        wellingtonsquare:{lat: wellingtonsquare.lat,lng: wellingtonsquare.lng, radius: wellingtonsquare.radius},
        ManresaRd:{lat: ManresaRd.lat,lng: ManresaRd.lng, radius: ManresaRd.radius},
        KingsRd:{lat: KingsRd.lat,lng: KingsRd.lng, radius: KingsRd.radius},
        OakleyGardens:{lat: OakleyGardens.lat,lng: OakleyGardens.lng, radius: OakleyGardens.radius},
        StLooAve:{lat: StLooAve.lat,lng: StLooAve.lng, radius: StLooAve.radius},
        eastroad:{lat: eastroad.lat,lng: eastroad.lng, radius: eastroad.radius},
        ElmParkRd:{lat: ElmParkRd.lat,lng: ElmParkRd.lng, radius: ElmParkRd.radius},
        MulberryWalk:{lat: MulberryWalk.lat,lng: MulberryWalk.lng, radius: MulberryWalk.radius},
        ParkWalk:{lat: ParkWalk.lat,lng: ParkWalk.lng, radius: ParkWalk.radius},
        beaufortst:{lat: beaufortst.lat,lng: beaufortst.lng, radius: beaufortst.radius},
        MoravianPl:{lat: MoravianPl.lat,lng: MoravianPl.lng, radius: MoravianPl.radius},
        annlane:{lat: annlane.lat,lng: annlane.lng, radius: annlane.radius},
        EdithYard:{lat: EdithYard.lat,lng: EdithYard.lng, radius: EdithYard.radius},
        AshburnhamRoad:{lat: AshburnhamRoad.lat,lng: AshburnhamRoad.lng, radius: AshburnhamRoad.radius},
        thorndickcl:{lat: thorndickcl.lat,lng: thorndickcl.lng, radius: thorndickcl.radius},
        FullhamRoad:{lat: FullhamRoad.lat,lng: FullhamRoad.lng, radius: FullhamRoad.radius},
        TheTrafalgar: {lat:TheTrafalgar.lat,lng: TheTrafalgar.lng,radius:25}
  
      }
  
      // Robbery / Burglary / Shoplifting
      const RBSLocations = {HorseGuardsAve: {lat:HorseGuardsAve.lat, lng: HorseGuardsAve.lng, radius: HorseGuardsAve.radius},
      MatthewParkerSt: {lat: MatthewParkerSt.lat,lng: MatthewParkerSt.lng,radius: MatthewParkerSt.radius},
      CaxtonSt: {lat: CaxtonSt.lat,lng: CaxtonSt.lng,radius: CaxtonSt.radius},
      B323: {lat: B323.lat,lng: B323.lng,radius: B323.radius},
      SaintMatthewSt: {lat: SaintMatthewSt.lat,lng: SaintMatthewSt.lng,radius: SaintMatthewSt.radius},
      MonckStreet: {lat: MonckStreet.lat,lng: MonckStreet.lng,radius: MonckStreet.radius},
      HidePlace: {lat: HidePlace.lat,lng: HidePlace.lng,radius: HidePlace.radius},
      WillowPlace: {lat: WillowPlace.lat,lng: WillowPlace.lng,radius: WillowPlace.radius},
      DouglasSt: {lat: DouglasSt.lat,lng: DouglasSt.lng,radius: DouglasSt.radius},
      BeestonPlace: {lat: BeestonPlace.lat,lng: BeestonPlace.lng,radius: BeestonPlace.radius},
      VictoriaSqr: {lat: VictoriaSqr.lat,lng: VictoriaSqr.lng,radius: VictoriaSqr.radius},
      AllingtonSt: {lat: AllingtonSt.lat,lng: AllingtonSt.lng,radius: AllingtonSt.radius},
      VauxhallBridgeRd: {lat: VauxhallBridgeRd.lat,lng: VauxhallBridgeRd.lng,radius: VauxhallBridgeRd.radius},
      AmbrosdenAve: {lat: AmbrosdenAve.lat,lng: AmbrosdenAve.lng,radius: AmbrosdenAve.radius},
      HowichPlace: {lat: HowichPlace.lat,lng: HowichPlace.lng,radius: HowichPlace.radius},
      StillingtonSt: {lat: StillingtonSt.lat,lng: StillingtonSt.lng,radius: StillingtonSt.radius},
      CardinalWalk: {lat: CardinalWalk.lat,lng: CardinalWalk.lng,radius: CardinalWalk.radius},
      WarwichRow: {lat: WarwichRow.lat,lng: WarwichRow.lng,radius: WarwichRow.radius},
      KingsRd:{lat: KingsRd.lat, lng: KingsRd.lng,radius:10},
      BeauchampPlace: {lat: BeauchampPlace.lat, lng: BeauchampPlace.lng, radius: BeauchampPlace.radius},
      WaltonStreet: {lat: WaltonStreet.lat, lng: WaltonStreet.lng, radius: WaltonStreet.radius},
      MilnerSt: {lat: MilnerSt.lat, lng: MilnerSt.lng, radius: MilnerSt.radius},
      PavilionSt: {lat: PavilionSt.lat, lng: PavilionSt.lng, radius: PavilionSt.radius},
      CadoganSt: {lat: CadoganSt.lat, lng: CadoganSt.lng, radius: CadoganSt.radius},
      SloaneAvenue: {lat: SloaneAvenue.lat, lng: SloaneAvenue.lng, radius: SloaneAvenue.radius},
      burywalk: {lat: burywalk.lat, lng: burywalk.lng, radius: burywalk.radius},
      LincolnSt: {lat: LincolnSt.lat, lng: LincolnSt.lng, radius: LincolnSt.radius},
      CulfordGardens: {lat: CulfordGardens.lat, lng: CulfordGardens.lng, radius: CulfordGardens.radius},
      SymonsStreet: {lat: SymonsStreet.lat, lng: SymonsStreet.lng, radius: SymonsStreet.radius},
      ParkingArea: {lat: ParkingArea.lat, lng: ParkingArea.lng, radius: ParkingArea.radius},
      CoulsonSt: {lat: CoulsonSt.lat, lng: CoulsonSt.lng, radius: CoulsonSt.radius},
      BywaterSt: {lat: BywaterSt.lat, lng: BywaterSt.lng, radius: BywaterSt.radius},
      DanuseStreet: {lat: DanuseStreet.lat, lng: DanuseStreet.lng, radius: DanuseStreet.radius},
      SParade: {lat: SParade.lat, lng: SParade.lng, radius: SParade.radius},
      DovehouseSt: {lat: DovehouseSt.lat, lng: DovehouseSt.lng, radius: DovehouseSt.radius},
      TheTrafalgar: {lat: TheTrafalgar.lat, lng: TheTrafalgar.lng, radius: TheTrafalgar.radius},
      MarksAndSpencer: {lat: MarksAndSpencer.lat, lng: MarksAndSpencer.lng, radius: MarksAndSpencer.radius},
      WoodfallSt: {lat: WoodfallSt.lat, lng: WoodfallSt.lng, radius: WoodfallSt.radius},
      StLeonardsTerrace: {lat: StLeonardsTerrace.lat, lng: StLeonardsTerrace.lng, radius: StLeonardsTerrace.radius},
      ChelseaManorGardens: {lat: ChelseaManorGardens.lat, lng: ChelseaManorGardens.lng, radius: ChelseaManorGardens.radius},
      CheyneWalk: {lat: CheyneWalk.lat, lng: CheyneWalk.lng, radius: CheyneWalk.radius},
      EastRoad: {lat: EastRoad.lat, lng: EastRoad.lng, radius: EastRoad.radius},
      PaultonsSquare: {lat: PaultonsSquare.lat, lng: PaultonsSquare.lng, radius: PaultonsSquare.radius},
      MallordSt: {lat: MallordSt.lat, lng: MallordSt.lng, radius: MallordSt.radius},
      FullhamRd: {lat: FullhamRd.lat, lng: FullhamRd.lng, radius: FullhamRd.radius},
      WintertonPlace: {lat: WintertonPlace.lat, lng: WintertonPlace.lng, radius: WintertonPlace.radius},
      SlaidburnSt: {lat: SlaidburnSt.lat, lng: SlaidburnSt.lng, radius: SlaidburnSt.radius},
      BlantyreStreet: {lat: BlantyreStreet.lat, lng: BlantyreStreet.lng, radius: BlantyreStreet.radius},
      EdithGrove: {lat: EdithGrove.lat, lng: EdithGrove.lng, radius: EdithGrove.radius},
      upcernerd: {lat: upcernerd.lat, lng: upcernerd.lng, radius: upcernerd.radius},
      hortensiaroad: {lat: hortensiaroad.lat, lng: hortensiaroad.lng, radius: hortensiaroad.radius}
    }
  
    //   // Vehicles
      const VehicleLocations = {DacreSreet: {lat: DacreSreet.lat, lng: DacreSreet.lng, radius:DacreSreet.radius},
        MonckSt: {lat: MonckSt.lat, lng: MonckSt.lng, radius:MonckSt.radius},
        RutherfordSt: {lat: RutherfordSt.lat, lng: RutherfordSt.lng, radius:RutherfordSt.radius},
        EsterbrookeSt: {lat: EsterbrookeSt.lat, lng: EsterbrookeSt.lng, radius:EsterbrookeSt.radius},
        PonsonbyPlace: {lat: PonsonbyPlace.lat, lng: PonsonbyPlace.lng, radius:PonsonbyPlace.radius},
        ThirlebyRd: {lat: ThirlebyRd.lat, lng: ThirlebyRd.lng, radius:ThirlebyRd.radius},
        HowichPl: {lat: HowichPl.lat, lng: HowichPl.lng, radius:HowichPl.radius},
        BeauchampPl: {lat: BeauchampPl.lat, lng: BeauchampPl.lng, radius:BeauchampPl.radius},
        EgertonGardens: {lat: EgertonGardens.lat, lng: EgertonGardens.lng, radius:EgertonGardens.radius},
        EgertonGardens_two: {lat: EgertonGardens_two.lat, lng: EgertonGardens_two.lng, radius:EgertonGardens_two.radius},
        OvingstonStreet: {lat: OvingstonStreet.lat, lng: OvingstonStreet.lng, radius:OvingstonStreet.radius},
        CrescentPlace: {lat: CrescentPlace.lat, lng: CrescentPlace.lng, radius:CrescentPlace.radius},
        HalseySt: {lat: HalseySt.lat, lng: HalseySt.lng, radius:HalseySt.radius},
        MilnerStreet: {lat: MilnerStreet.lat, lng: MilnerStreet.lng, radius:MilnerStreet.radius},
        ShafloMews: {lat: ShafloMews.lat, lng: ShafloMews.lng, radius:ShafloMews.radius},
        CadoganGardens: {lat: CadoganGardens.lat, lng: CadoganGardens.lng, radius:CadoganGardens.radius},
        DraycottAvenue: {lat: DraycottAvenue.lat, lng: DraycottAvenue.lng, radius:DraycottAvenue.radius},
        SloaneAve: {lat: SloaneAve.lat, lng: SloaneAve.lng, radius:SloaneAve.radius},
        SprimontPl: {lat: SprimontPl.lat, lng: SprimontPl.lng, radius:SprimontPl.radius},
        JubileePl: {lat: JubileePl.lat, lng: JubileePl.lng, radius:JubileePl.radius},
        WellingtonSquare: {lat: WellingtonSquare.lat, lng: WellingtonSquare.lng, radius:WellingtonSquare.radius},
        DovehouseStreet: {lat: DovehouseStreet.lat, lng: DovehouseStreet.lng, radius:DovehouseStreet.radius},
        stleonardsterrace: {lat: stleonardsterrace.lat, lng: stleonardsterrace.lng, radius:stleonardsterrace.radius},
        ManresaRoad: {lat: ManresaRoad.lat, lng: ManresaRoad.lng, radius:ManresaRoad.radius},
        CheyneGardens: {lat: CheyneGardens.lat, lng: CheyneGardens.lng, radius:CheyneGardens.radius},
        RoyalHospitalRoad: {lat: RoyalHospitalRoad.lat, lng: RoyalHospitalRoad.lng, radius:RoyalHospitalRoad.radius},
        ParadiseWalk: {lat: ParadiseWalk.lat, lng: ParadiseWalk.lng, radius:ParadiseWalk.radius},
        FranklinsRow: {lat: FranklinsRow.lat, lng: FranklinsRow.lng, radius:FranklinsRow.radius},
        SloaneCourtWest: {lat: SloaneCourtWest.lat, lng: SloaneCourtWest.lng, radius:SloaneCourtWest.radius},
        LordshipPl: {lat: LordshipPl.lat, lng: LordshipPl.lng, radius:LordshipPl.radius},
        OldChurchStreet: {lat: OldChurchStreet.lat, lng: OldChurchStreet.lng, radius:OldChurchStreet.radius},
        elmparkgarndens: {lat: elmparkgarndens.lat, lng: elmparkgarndens.lng, radius:elmparkgarndens.radius},
        kingsroad: {lat: kingsroad.lat, lng: kingsroad.lng, radius:kingsroad.radius},
        parkwalk: {lat: parkwalk.lat, lng: parkwalk.lng, radius:parkwalk.radius},
        BeaufortSt: {lat: BeaufortSt.lat, lng: BeaufortSt.lng, radius:BeaufortSt.radius},
        LamontRoadPassage: {lat: LamontRoadPassage.lat, lng: LamontRoadPassage.lng, radius:LamontRoadPassage.radius},
        limerstonstreet: {lat: limerstonstreet.lat, lng: limerstonstreet.lng, radius:limerstonstreet.radius},
        GertrudeStreet: {lat: GertrudeStreet.lat, lng: GertrudeStreet.lng, radius:GertrudeStreet.radius},
        LamontRoad: {lat: LamontRoad.lat, lng: LamontRoad.lng, radius:LamontRoad.radius},
        LangtonStreet: {lat: LangtonStreet.lat, lng: LangtonStreet.lng, radius:LangtonStreet.radius},
        TademaRoad: {lat: TademaRoad.lat, lng: TademaRoad.lng, radius:TademaRoad.radius},
        UpcerneRd: {lat: UpcerneRd.lat, lng: UpcerneRd.lng, radius:UpcerneRd.radius},
        LotsRd: {lat: LotsRd.lat, lng: LotsRd.lng, radius:LotsRd.radius},
        HortensiaRd: {lat: HortensiaRd.lat, lng: HortensiaRd.lng, radius:HortensiaRd.radius}
      }
  
      // Scams
      const ScamsLocations = {WestminsterBridge: {lat: WestminsterBridge.lat, lng: WestminsterBridge.lng, radius: WestminsterBridge.radius},
        DaycottsApartments: {lat: DaycottsApartments.lat, lng: DaycottsApartments.lng, radius: DaycottsApartments.radius},
        IvyChelseaGarden: {lat: IvyChelseaGarden.lat, lng: IvyChelseaGarden.lng, radius: IvyChelseaGarden.radius},
        sloaneave: {lat: sloaneave.lat, lng: sloaneave.lng, radius: sloaneave.radius},
        RoyalHospitalRd: {lat: RoyalHospitalRd.lat, lng: RoyalHospitalRd.lng, radius: RoyalHospitalRd.radius}
      }
  
      // Check and Display the number of dangerous locations through a selected travel
    // Violence Circles
    let Violence = 0;
    for(const violentlocation in ViolenceLocations) {
      const circle = ViolenceLocations[violentlocation]
      for(const coordinate of routeCoordinates) {
        const distanceToCenter = google.maps.geometry.spherical.computeDistanceBetween(
          new google.maps.LatLng(coordinate.lat(),coordinate.lng()),
          new google.maps.LatLng(circle.lat, circle.lng)
        );
        if (distanceToCenter <= circle.radius) {
          Violence++;
          console.log(`Route entered ${violentlocation} circle radius!`);
          break;
        }
      }
    }
  //Theft Circles
    let theftCount = 0;
    for(const theftlocation in TheftLocations) {
      const circle = TheftLocations[theftlocation]
      for(const coordinate of routeCoordinates) {
        const distanceToCenter = google.maps.geometry.spherical.computeDistanceBetween(
          new google.maps.LatLng(coordinate.lat(),coordinate.lng()),
          new google.maps.LatLng(circle.lat, circle.lng)
        );
        if (distanceToCenter <= circle.radius) {
          theftCount++;
          console.log(`Route entered ${theftlocation} circle radius!`);
          break;
        }
      }
    }
  // Robbery/Burglary/Shoplifting Circles
    let RBSCount = 0;
      for(const RBSlocation in RBSLocations) {
        const circle = RBSLocations[RBSlocation]
        for(const coordinate of routeCoordinates) {
          const distanceToCenter = google.maps.geometry.spherical.computeDistanceBetween(
            new google.maps.LatLng(coordinate.lat(),coordinate.lng()),
            new google.maps.LatLng(circle.lat, circle.lng)
          );
          if (distanceToCenter <= circle.radius) {
            RBSCount++;
            console.log(`Route entered ${RBSlocation} circle radius!`);
            break;
          }
        }
      }
  // Vehicle Crime Circles
   let VehicleCrimeCounts = 0;
      for(const vehiclelocation in VehicleLocations) {
        const circle = VehicleLocations[vehiclelocation]
        for(const coordinate of routeCoordinates) {
          const distanceToCenter = google.maps.geometry.spherical.computeDistanceBetween(
            new google.maps.LatLng(coordinate.lat(),coordinate.lng()),
            new google.maps.LatLng(circle.lat, circle.lng)
          );
          if (distanceToCenter <= circle.radius) {
            VehicleCrimeCounts++;
            console.log(`Route entered ${vehiclelocation} circle radius!`);
            break;
          }
        }
      }
  // Scam Circles
    let Scams = 0;
    for(const Scamlocation in ScamsLocations) {
      const circle = ScamsLocations[Scamlocation]
      for(const coordinate of routeCoordinates) {
        const distanceToCenter = google.maps.geometry.spherical.computeDistanceBetween(
          new google.maps.LatLng(coordinate.lat(),coordinate.lng()),
          new google.maps.LatLng(circle.lat, circle.lng)
        );
        if (distanceToCenter <= circle.radius) {
          Scams++;
          console.log(`Route entered ${Scamlocation} circle radius!`);
          break;
        }
      }
    }
  
      setDirectionResponse(results)
      setDistance(results.routes[0].legs[0].distance.text)
      setDuration(results.routes[0].legs[0].duration.text)
  // Display the amounts
      alert(`Througout your travel you will encounter - Theft areas: ${theftCount}, Violence areas: ${Violence}, Robbery/Burglary/Shoplifting areas: ${RBSCount}, VehicleCrime areas: ${VehicleCrimeCounts} and Scam areas: ${Scams}
      (Click Ok to end this message and see your route and Click Calculate Route to view this again)`)
  
      }
    // Select travel mode
     function getGoogleMapsTravelMode(selectTravelMode) {
      switch(selectTravelMode) {
        case 'Walking':
          return google.maps.TravelMode.WALKING;
        case 'Bicycling':
          return google.maps.TravelMode.BICYCLING;
        case 'Driving':
          return google.maps.TravelMode.DRIVING;
        case 'Public Transport':
          return google.maps.TravelMode.TRANSIT;
      }
     }
     function clearRoute() {
      setDirectionResponse(null)
      setDistance('')
      setDuration('')
      originRef.current.value = ''
      destionationRef.current.value = ''
     }
  
     var UserlocationLat = 0;
     var UserlocationLng = 0;
     const Userlocation = {lat: UserlocationLat, lng: UserlocationLng};
  
    findMyCoordinates();
  
  
     function findMyCoordinates() {
      if(navigator.geolocation) {
        navigator.geolocation.getCurrentPosition((position) => {
          console.log(position.coords.latitude, position.coords.longitude)
          UserlocationLat = position.coords.latitude
          UserlocationLng = position.coords.longitude
  
          Userlocation.lat = UserlocationLat;
          Userlocation.lng = UserlocationLng;
  
        },
        (err) => {
          alert(err.message)
        })
  
      } else {
        alert("Geolocation is not supported by your browser")
      }
     }
  
  
    return (
      <Flex
        position='relative'
        flexDirection='column'
        alignItems='center'
        bgColor='blue.200'
        h='100vh'
        w='100vw'
      >
        <Box position='absolute' left={0} top={0} h='100%' w='100%'>
          {/* google maps* Api */}
          <GoogleMap 
          center={center} 
          zoom= {15} 
          mapContainerStyle={{width: '100%', height: '100%'}}
          
          onLoad={(map) => { 
            setMap(map)
            //Circle around goldsmiths test
          //   const circle = new google.maps.Circle({
          //     strokeColor: '#FF0000',
          //     strokeWeight: 2,
          //     strokeOpacity: 1,
          //     fillColor: '#FF0000',
          //     fillOpacity: .4,
          //     center: center,
          //     radius: 100,
          //     map: map
          //   });
          // setMap(circle)
            
            //Westminster
            //Violence
            const V1 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: WhitehallCt,
              radius: 30,
              map: map
            });
          setMap(V1)
  
            const V2 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: ParliamentSt,
                radius: 50,
                map: map
              });
            setMap(V2)
  
            const V3 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: WestminsterPier,
                radius: 50,
                map: map
              });
            setMap(V3)
  
            const V4 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: WestminsterArms,
              radius: 20,
              map: map
            });
            setMap(V4)
  
            const V5 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: CarteretSt,
              radius: 15,
              map: map
            });
            setMap(V5)
  
            const V6 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: DacreSt,
              radius: 15,
              map: map
            });
            setMap(V6)
  
            const V7 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: StarbucksCoffee,
              radius: 15,
              map: map
            });
            setMap(V7)
  
            const V8 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: VictoriaSt,
              radius: 10,
              map: map
            });
            setMap(V8)
  
            const V9 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: OldPyeSt,
              radius: 40,
              map: map
            });
            setMap(V9)
  
            const V10 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: StMatthewStreet,
              radius: 10,
              map: map
            });
            setMap(V10)
  
            const V11 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: GreycoatPlace,
              radius: 10,
              map: map
            });
            setMap(V11)
  
            const V12 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: GreatPeterStreet,
              radius: 50,
              map: map
            });
            setMap(V12)
            const V13 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: DeanTrenchSt,
              radius: 10,
              map: map
            });
            setMap(V13)
  
            const V14 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: HorseferryRd,
              radius: 20,
              map: map
            });
            setMap(V14)
  
            const V15 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: ArnewaySt,
              radius: 20,
              map: map
            });
            setMap(V15)
  
            const V16 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: ChadwichSt,
              radius: 20,
              map: map
            });
            setMap(V16)
  
            const V17 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: ThorneySt,
              radius: 10,
              map: map
            });
            setMap(V17)
  
            const V18 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: PageSt,
              radius: 20,
              map: map
            });
            setMap(V18)
  
            const V19 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: RegencySt,
              radius: 20,
              map: map
            });
            setMap(V19)
  
            const V20 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: VincentStreet,
              radius: 20,
              map: map
            });
            setMap(V20)
  
            const V21 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: RegencyStreet,
              radius: 10,
              map: map
            });
            setMap(V21)
  
            const V22 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: WalcottSt,
              radius: 10,
              map: map
            });
            setMap(V22)
  
            
            const V23 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: VauxhallBridgeRoad,
              radius: 10,
              map: map
            });
            setMap(V23)
  
            const V24 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: HatherleyStreet,
              radius: 10,
              map: map
            });
            setMap(V24)
  
            const V25 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: HerrickSt,
              radius: 25,
              map: map
            });
            setMap(V25)
  
            const V26 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: CuretonSt,
              radius: 15,
              map: map
            });
            setMap(V26)
  
            const V27 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: AtterburySt,
              radius: 15,
              map: map
            });
            setMap(V27)
  
            const V28 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: VictoriaStreet,
              radius: 50,
              map: map
            });
            setMap(V28)
  
            const V29 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: ThirlebyRoad,
              radius: 20,
              map: map
            });
            setMap(V29)
  
            const V30 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: GreencoatRow,
              radius: 10,
              map: map
            });
            setMap(V30)
  
            const V31 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: FrancisSt,
              radius: 15,
              map: map
            });
            setMap(V31)
  
            const V32 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: MorpethTerrace, 
              radius: 10,
              map: map
            });
            setMap(V32)
  
            const V33 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: StillingtonStreet, 
              radius: 10,
              map: map
            });
            setMap(V33)
  
            const V34 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: SpenserStreet, 
              radius: 15,
              map: map
            });
            setMap(V34)
  
            const V35 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: VandonStreet, 
              radius: 10,
              map: map
            });
            setMap(V35)
  
            const V36 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: BuckinghamGate, 
              radius: 10,
              map: map
            });
            setMap(V36)
  
            const V37 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: PalaceStreet, 
              radius: 20,
              map: map
            });
            setMap(V37)
  
            const V38 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: OvingtonMews, 
              radius: 10,
              map: map
            });
            setMap(V38)
  
            const V39 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: EgertonGardensMews, 
              radius: 10,
              map: map
            });
            setMap(V39)
  
            const V40 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: HaskerStreet, 
              radius: 10,
              map: map
            });
            setMap(V40)
  
            const V41 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: CadoganGate, 
              radius: 10,
              map: map
            });
            setMap(V41)
  
            const V42 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: RawlingsSt, 
              radius: 20,
              map: map
            });
            setMap(V42)
  
            const V43 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: DraycottAve, 
              radius: 15,
              map: map
            });
            setMap(V43)
  
            const V44 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: MakinsSt, 
              radius: 15,
              map: map
            });
            setMap(V44)
  
            const V45 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: IxworthPlace, 
              radius: 10,
              map: map
            });
            setMap(V45)
  
            const V46 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: BuryWalk, 
              radius: 20,
              map: map
            });
            setMap(V46)
  
            const V47 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: DanuseSt, 
              radius: 10,
              map: map
            });
            setMap(V47)
  
            const V48 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: CaleSt, 
              radius: 10,
              map: map
            });
            setMap(V48)
  
            const V49 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: TheTrafalgar, 
              radius: 15,
              map: map
            });
            setMap(V49)
  
            const V50 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: KingsRd, 
              radius: 15,
              map: map
            });
            setMap(V50)
  
            const V51 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: FloodWalk, 
              radius: 25,
              map: map
            });
            setMap(V51)
  
            const V52 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: roalhospitalroad, 
              radius: 10,
              map: map
            });
            setMap(V52)
  
            const V53 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: PetytPlace, 
              radius: 10,
              map: map
            });
            setMap(V53)
  
            const V54 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: DanversSt, 
              radius: 10,
              map: map
            });
            setMap(V54)
  
            const V55 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: CarlyleSquare, 
              radius: 10,
              map: map
            });
            setMap(V55)
  
            const V56 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: ElmParkGardens, 
              radius: 10,
              map: map
            });
            setMap(V56)
  
            const V57 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: kingsrd, 
              radius: 10,
              map: map
            });
            setMap(V57)
  
            const V58 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: PeonyCourt, 
              radius: 15,
              map: map
            });
            setMap(V58)
  
            const V59 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: ChelseaParkGardens, 
              radius: 10,
              map: map
            });
            setMap(V59)
  
            const V60 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: BeaufordStreet,
              radius: 10,
              map: map
            });
            setMap(V60)
  
            const V61 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center:lamontroadpassage,
              radius: 10,
              map: map
            });
            setMap(V61)
  
            const V62 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center:LimerstonStreet,
              radius: 10,
              map: map
            });
            setMap(V62)
  
            const V63 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: NightingalePl,
              radius: 10,
              map: map
            });
            setMap(V63)
  
            const V64 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: LangtonSt,
              radius: 10,
              map: map
            });
            setMap(V64)
  
            const V65 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: RileySt,
              radius: 10,
              map: map
            });
            setMap(V65)
  
            const V66 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: AnnLane,
              radius: 15,
              map: map
            });
            setMap(V66)
  
            const V67 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: EdithGroveCarPark,
              radius: 10,
              map: map
            });
            setMap(V67)
  
            const V68 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: ChelseaTheatre,
              radius: 20,
              map: map
            });
            setMap(V68)
  
            const V69 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: edithgrove,
              radius: 10,
              map: map
            });
            setMap(V69)
  
            const V70 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: lotsrd,
              radius: 10,
              map: map
            });
            setMap(V70)
  
            const V71 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: ThorndickCl,
              radius: 15,
              map: map
            });
            setMap(V71)
  
            const V72 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: fullhamroad,
              radius: 15,
              map: map
            });
            setMap(V72)
  
            const V73 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: FawcettStreet,
              radius: 15,
              map: map
            });
            setMap(V73)
  
            const V74 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: HollywoodRoad,
              radius: 10,
              map: map
            });
            setMap(V74)
  
            const V75 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: HarleyGardens,
              radius: 10,
              map: map
            });
            setMap(V75)
  
            const V76 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: IfieldRoad,
              radius: 10,
              map: map
            });
            setMap(V76)
  
            const V77 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: RedcliffeStreet,
              radius: 10,
              map: map
            });
            setMap(V77)
  
            const V78 = new google.maps.Circle({
              strokeColor: '#FF0000',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FF0000',
              fillOpacity: .4,
              center: TregunterRoad,
              radius: 10,
              map: map
            });
            setMap(V78)
  
  
          //Theft
            const T1 = new google.maps.Circle({
              strokeColor: '#00FF00',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#00FF00',
              fillOpacity: .4,
              center: ScotlandYard,
              radius: 30,
              map: map
            });
          setMap(T1)
  
            const T2 = new google.maps.Circle({
              strokeColor: '#00FF00',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#00FF00',
              fillOpacity: .4,
              center: KoreanCC,
              radius: 20,
              map: map
            });
          setMap(T2)
  
            const T3 = new google.maps.Circle({
              strokeColor: '#00FF00',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#00FF00',
              fillOpacity: .4,
              center: CraigCt,
              radius: 50,
              map: map
            });
          setMap(T3)
  
            const T4 = new google.maps.Circle({
              strokeColor: '#00FF00',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#00FF00',
              fillOpacity: .4,
              center: QueenElizabethCentre,
              radius: 40,
              map: map
            });
          setMap(T4)
  
            const T5 = new google.maps.Circle({
              strokeColor: '#00FF00',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#00FF00',
              fillOpacity: .4,
              center: MargaretChurch,
              radius: 40,
              map: map
            });
          setMap(T5)
  
            const T6 = new google.maps.Circle({
              strokeColor: '#00FF00',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#00FF00',
              fillOpacity: .4,
              center: TescoExpress,
              radius: 60,
              map: map
            });
          setMap(T6)
            const T7 = new google.maps.Circle({
              strokeColor: '#00FF00',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#00FF00',
              fillOpacity: .4,
              center: GeorgeStreet,
              radius: 30,
              map: map
            });
          setMap(T7)
  
            const T8 = new google.maps.Circle({
              strokeColor: '#00FF00',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#00FF00',
              fillOpacity: .4,
              center: OldQueenSt,
              radius: 30,
              map: map
            });
          setMap(T8)
  
            const T9 = new google.maps.Circle({
              strokeColor: '#00FF00',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#00FF00',
              fillOpacity: .4,
              center: Broadway,
              radius: 10,
              map: map
            });
          setMap(T9)
  
            const T10 = new google.maps.Circle({
              strokeColor: '#00FF00',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#00FF00',
              fillOpacity: .4,
              center: TheSanctuary,
              radius: 10,
              map: map
            });
          setMap(T10)
          const T11 = new google.maps.Circle({
            strokeColor: '#00FF00',
            strokeWeight: 2,
            strokeOpacity: 1,
            fillColor: '#00FF00',
            fillOpacity: .4,
            center: PalmerSt,
            radius: 10,
            map: map
          });
        setMap(T11)
  
          const T12 = new google.maps.Circle({
            strokeColor: '#00FF00',
            strokeWeight: 2,
            strokeOpacity: 1,
            fillColor: '#00FF00',
            fillOpacity: .4,
            center: B323St,
            radius: 10,
            map: map
          });
        setMap(T12)
  
          const T13 = new google.maps.Circle({
            strokeColor: '#00FF00',
            strokeWeight: 2,
            strokeOpacity: 1,
            fillColor: '#00FF00',
            fillOpacity: .4,
            center: StMatthewSt,
            radius: 40,
            map: map
          });
        setMap(T13)
  
        const T14 = new google.maps.Circle({
          strokeColor: '#00FF00',
          strokeWeight: 2,
          strokeOpacity: 1,
          fillColor: '#00FF00',
          fillOpacity: .4,
          center: RochesterRow,
          radius: 10,
          map: map
        });
      setMap(T14)
  
        const T15 = new google.maps.Circle({
          strokeColor: '#00FF00',
          strokeWeight: 2,
          strokeOpacity: 1,
          fillColor: '#00FF00',
          fillOpacity: .4,
          center: GreatSmithSt,
          radius: 10,
          map: map
        });
      setMap(T15)
  
        const T16 = new google.maps.Circle({
          strokeColor: '#00FF00',
          strokeWeight: 2,
          strokeOpacity: 1,
          fillColor: '#00FF00',
          fillOpacity: .4,
          center: GreatPeterSt,
          radius: 15,
          map: map
        });
      setMap(T16)
  
        const T17 = new google.maps.Circle({
          strokeColor: '#00FF00',
          strokeWeight: 2,
          strokeOpacity: 1,
          fillColor: '#00FF00',
          fillOpacity: .4,
          center: TuftonSt,
          radius: 15,
          map: map
        });
      setMap(T17)
  
        const T18 = new google.maps.Circle({
          strokeColor: '#00FF00',
          strokeWeight: 2,
          strokeOpacity: 1,
          fillColor: '#00FF00',
          fillOpacity: .4,
          center: BennettYard,
          radius: 18,
          map: map
        });
      setMap(T18)
  
        const T19 = new google.maps.Circle({
          strokeColor: '#00FF00',
          strokeWeight: 2,
          strokeOpacity: 1,
          fillColor: '#00FF00',
          fillOpacity: .4,
          center: SmithSquare,
          radius: 10,
          map: map
        });
      setMap(T19)
  
        const T20 = new google.maps.Circle({
          strokeColor: '#00FF00',
          strokeWeight: 2,
          strokeOpacity: 1,
          fillColor: '#00FF00',
          fillOpacity: .4,
          center: RomneySt,
          radius: 10,
          map: map
        });
      setMap(T20)
  
        const T21 = new google.maps.Circle({
          strokeColor: '#00FF00',
          strokeWeight: 2,
          strokeOpacity: 1,
          fillColor: '#00FF00',
          fillOpacity: .4,
          center: HorseferryRoad,
          radius: 20,
          map: map
        });
      setMap(T21)
  
        const T22 = new google.maps.Circle({
          strokeColor: '#00FF00',
          strokeWeight: 2,
          strokeOpacity: 1,
          fillColor: '#00FF00',
          fillOpacity: .4,
          center: MedwaySt,
          radius: 25,
          map: map
        });
      setMap(T22)
  
        const T23 = new google.maps.Circle({
          strokeColor: '#00FF00',
          strokeWeight: 2,
          strokeOpacity: 1,
          fillColor: '#00FF00',
          fillOpacity: .4,
          center: ChadwichStreet,
          radius: 25,
          map: map
        });
      setMap(T23)
  
        const T24 = new google.maps.Circle({
          strokeColor: '#00FF00',
          strokeWeight: 2,
          strokeOpacity: 1,
          fillColor: '#00FF00',
          fillOpacity: .4,
          center: PageStreet,
          radius: 40,
          map: map
        });
      setMap(T24)
  
        const T25 = new google.maps.Circle({
          strokeColor: '#00FF00',
          strokeWeight: 2,
          strokeOpacity: 1,
          fillColor: '#00FF00',
          fillOpacity: .4,
          center: MaunselSt,
          radius: 20,
          map: map
        });
      setMap(T25)
  
        const T26 = new google.maps.Circle({
          strokeColor: '#00FF00',
          strokeWeight: 2,
          strokeOpacity: 1,
          fillColor: '#00FF00',
          fillOpacity: .4,
          center: RochesterSt,
          radius: 10,
          map: map
        });
      setMap(T26)
  
        const T27 = new google.maps.Circle({
          strokeColor: '#00FF00',
          strokeWeight: 2,
          strokeOpacity: 1,
          fillColor: '#00FF00',
          fillOpacity: .4,
          center: VincentSt,
          radius: 30,
          map: map
        });
      setMap(T27)
  
        const T28 = new google.maps.Circle({
          strokeColor: '#00FF00',
          strokeWeight: 2,
          strokeOpacity: 1,
          fillColor: '#00FF00',
          fillOpacity: .4,
          center: HatherleySt,
          radius: 10,
          map: map
        });
      setMap(T28)
  
        const T29 = new google.maps.Circle({
          strokeColor: '#00FF00',
          strokeWeight: 2,
          strokeOpacity: 1,
          fillColor: '#00FF00',
          fillOpacity: .4,
          center: DouglasStreet,
          radius: 10,
          map: map
        });
      setMap(T29)
  
        const T30 = new google.maps.Circle({
          strokeColor: '#00FF00',
          strokeWeight: 2,
          strokeOpacity: 1,
          fillColor: '#00FF00',
          fillOpacity: .4,
          center: Millbank,
          radius: 20,
          map: map
        });
      setMap(T30)
  
        const T31 = new google.maps.Circle({
          strokeColor: '#00FF00',
          strokeWeight: 2,
          strokeOpacity: 1,
          fillColor: '#00FF00',
          fillOpacity: .4,
          center: BessboroughGardens,
          radius: 30,
          map: map
        });
      setMap(T31)
  
        const T32 = new google.maps.Circle({
          strokeColor: '#00FF00',
          strokeWeight: 2,
          strokeOpacity: 1,
          fillColor: '#00FF00',
          fillOpacity: .4,
          center: VictoriaSquare,
          radius: 20,
          map: map
        });
      setMap(T32)
  
        const T33 = new google.maps.Circle({
          strokeColor: '#00FF00',
          strokeWeight: 2,
          strokeOpacity: 1,
          fillColor: '#00FF00',
          fillOpacity: .4,
          center: LowerGrosvenorPlace,
          radius: 45,
          map: map
        });
      setMap(T33)
  
        const T34 = new google.maps.Circle({
          strokeColor: '#00FF00',
          strokeWeight: 2,
          strokeOpacity: 1,
          fillColor: '#00FF00',
          fillOpacity: .4,
          center:KingsScholarsPassage,
          radius: 30,
          map: map
        });
      setMap(T34)
  
        const T35 = new google.maps.Circle({
          strokeColor: '#00FF00',
          strokeWeight: 2,
          strokeOpacity: 1,
          fillColor: '#00FF00',
          fillOpacity: .4,
          center: AshleyPl,
          radius: 20,
          map: map
        });
      setMap(T35)
  
        const T36 = new google.maps.Circle({
          strokeColor: '#00FF00',
          strokeWeight: 2,
          strokeOpacity: 1,
          fillColor: '#00FF00',
          fillOpacity: .4,
          center: AmbrosdenAvenue,
          radius: 10,
          map: map
        });
      setMap(T36)
  
        const T37 = new google.maps.Circle({
          strokeColor: '#00FF00',
          strokeWeight: 2,
          strokeOpacity: 1,
          fillColor: '#00FF00',
          fillOpacity: .4,
          center: thirlebyrd,
          radius: 10,
          map: map
        });
      setMap(T37)
  
        const T38 = new google.maps.Circle({
          strokeColor: '#00FF00',
          strokeWeight: 2,
          strokeOpacity: 1,
          fillColor: '#00FF00',
          fillOpacity: .4,
          center: howichplace,
          radius: 90,
          map: map
        });
      setMap(T38)
  
        const T39 = new google.maps.Circle({
          strokeColor: '#00FF00',
          strokeWeight: 2,
          strokeOpacity: 1,
          fillColor: '#00FF00',
          fillOpacity: .4,
          center: ArtilleryRow,
          radius: 30,
          map: map
        });
      setMap(T39)
  
      
        const T40 = new google.maps.Circle({
          strokeColor: '#00FF00',
          strokeWeight: 2,
          strokeOpacity: 1,
          fillColor: '#00FF00',
          fillOpacity: .4,
          center: SpenserSt,
          radius: 30,
          map: map
        });
      setMap(T40)
  
        const T41 = new google.maps.Circle({
          strokeColor: '#00FF00',
          strokeWeight: 2,
          strokeOpacity: 1,
          fillColor: '#00FF00',
          fillOpacity: .4,
          center: FrancisStreet,
          radius: 20,
          map: map
        });
      setMap(T41)
  
        const T42 = new google.maps.Circle({
          strokeColor: '#00FF00',
          strokeWeight: 2,
          strokeOpacity: 1,
          fillColor: '#00FF00',
          fillOpacity: .4,
          center: VandonSt,
          radius: 20,
          map: map
        });
      setMap(T42)
  
      
        const T43 = new google.maps.Circle({
          strokeColor: '#00FF00',
          strokeWeight: 2,
          strokeOpacity: 1,
          fillColor: '#00FF00',
          fillOpacity: .4,
          center: QueenAnneGate,
          radius: 10,
          map: map
        });
      setMap(T43)
  
  
        const T44 = new google.maps.Circle({
          strokeColor: '#00FF00',
          strokeWeight: 2,
          strokeOpacity: 1,
          fillColor: '#00FF00',
          fillOpacity: .4,
          center: PalaceSt,
          radius: 20,
          map: map
        });
      setMap(T44)
  
      const T45 = new google.maps.Circle({
        strokeColor: '#00FF00',
        strokeWeight: 2,
        strokeOpacity: 1,
        fillColor: '#00FF00',
        fillOpacity: .4,
        center: Warwichrow,
        radius: 30,
        map: map
      });
    setMap(T45)
  
      const T46 = new google.maps.Circle({
        strokeColor: '#00FF00',
        strokeWeight: 2,
        strokeOpacity: 1,
        fillColor: '#00FF00',
        fillOpacity: .4,
        center: StaffordPlace,
        radius: 40,
        map: map
      });
    setMap(T46)
  
      const T47 = new google.maps.Circle({
        strokeColor: '#00FF00',
        strokeWeight: 2,
        strokeOpacity: 1,
        fillColor: '#00FF00',
        fillOpacity: .4,
        center: YeomanRow,
        radius: 10,
        map: map
      });
    setMap(T47)
  
      const T48 = new google.maps.Circle({
        strokeColor: '#00FF00',
        strokeWeight: 2,
        strokeOpacity: 1,
        fillColor: '#00FF00',
        fillOpacity: .4,
        center: EgertonTerrace,
        radius: 10,
        map: map
      });
    setMap(T48)
  
    const T49 = new google.maps.Circle({
      strokeColor: '#00FF00',
      strokeWeight: 2,
      strokeOpacity: 1,
      fillColor: '#00FF00',
      fillOpacity: .4,
      center: FirstSt,
      radius: 15,
      map: map
    });
  setMap(T49)
  
  const T50 = new google.maps.Circle({
    strokeColor: '#00FF00',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#00FF00',
    fillOpacity: .4,
    center: CrescentPl,
    radius: 20,
    map: map
  });
  setMap(T50)
  
  const T51 = new google.maps.Circle({
    strokeColor: '#00FF00',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#00FF00',
    fillOpacity: .4,
    center: ClabonMews,
    radius: 10,
    map: map
  });
  setMap(T51)
  
  const T52 = new google.maps.Circle({
    strokeColor: '#00FF00',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#00FF00',
    fillOpacity: .4,
    center: PavilionRd,
    radius: 10,
    map: map
  });
  setMap(T52)
  
  const T53 = new google.maps.Circle({
    strokeColor: '#00FF00',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#00FF00',
    fillOpacity: .4,
    center: CadoganStreet,
    radius: 10,
    map: map
  });
  setMap(T53)
  
  const T54 = new google.maps.Circle({
    strokeColor: '#00FF00',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#00FF00',
    fillOpacity: .4,
    center: DraycottTerrace,
    radius: 10,
    map: map
  });
  setMap(T54)
  
  const T55 = new google.maps.Circle({
    strokeColor: '#00FF00',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#00FF00',
    fillOpacity: .4,
    center: culfordgardens,
    radius: 15,
    map: map
  });
  setMap(T55)
  
  const T56 = new google.maps.Circle({
    strokeColor: '#00FF00',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#00FF00',
    fillOpacity: .4,
    center: SymonsSt,
    radius: 25,
    map: map
  });
  setMap(T56)
  
  
  const T57 = new google.maps.Circle({
    strokeColor: '#00FF00',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#00FF00',
    fillOpacity: .4,
    center: A3216,
    radius: 15,
    map: map
  });
  setMap(T57)
  
  const T58 = new google.maps.Circle({
    strokeColor: '#00FF00',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#00FF00',
    fillOpacity: .4,
    center: SaatchiGallery,
    radius: 40,
    map: map
  });
  setMap(T58)
  
  const T59 = new google.maps.Circle({
    strokeColor: '#00FF00',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#00FF00',
    fillOpacity: .4,
    center: parkingarea,
    radius: 20,
    map: map
  });
  setMap(T59)
  
  const T60 = new google.maps.Circle({
    strokeColor: '#00FF00',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#00FF00',
    fillOpacity: .4,
    center: MarkhamSquare,
    radius: 10,
    map: map
  });
  setMap(T60)
  
  const T61 = new google.maps.Circle({
    strokeColor: '#00FF00',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#00FF00',
    fillOpacity: .4,
    center: CaleStreet,
    radius: 15,
    map: map
  });
  setMap(T61)
  
  const T62 = new google.maps.Circle({
    strokeColor: '#00FF00',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#00FF00',
    fillOpacity: .4,
    center: wellingtonsquare,
    radius: 10,
    map: map
  });
  setMap(T62)
  
  const T63 = new google.maps.Circle({
    strokeColor: '#00FF00',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#00FF00',
    fillOpacity: .4,
    center: TheTrafalgar,
    radius: 25,
    map: map
  });
  setMap(T63)
  
  const T64 = new google.maps.Circle({
    strokeColor: '#00FF00',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#00FF00',
    fillOpacity: .4,
    center: ManresaRd,
    radius: 10,
    map: map
  });
  setMap(T64)
  
  const T65 = new google.maps.Circle({
    strokeColor: '#00FF00',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#00FF00',
    fillOpacity: .4,
    center: KingsRd,
    radius: 25,
    map: map
  });
  setMap(T65)
  
  const T66 = new google.maps.Circle({
    strokeColor: '#00FF00',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#00FF00',
    fillOpacity: .4,
    center: FloodWalk,
    radius: 10,
    map: map
  });
  setMap(T66)
  
  const T67 = new google.maps.Circle({
    strokeColor: '#00FF00',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#00FF00',
    fillOpacity: .4,
    center: OakleyGardens,
    radius: 10,
    map: map
  });
  setMap(T67)
  
  const T68 = new google.maps.Circle({
    strokeColor: '#00FF00',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#00FF00',
    fillOpacity: .4,
    center: StLooAve,
    radius: 10,
    map: map
  });
  setMap(T68)
  
  const T69 = new google.maps.Circle({
    strokeColor: '#00FF00',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#00FF00',
    fillOpacity: .4,
    center: eastroad,
    radius: 10,
    map: map
  });
  setMap(T69)
  
  const T70 = new google.maps.Circle({
    strokeColor: '#00FF00',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#00FF00',
    fillOpacity: .4,
    center: ElmParkRd,
    radius: 10,
    map: map
  });
  setMap(T70)
  
  const T71 = new google.maps.Circle({
    strokeColor: '#00FF00',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#00FF00',
    fillOpacity: .4,
    center: MulberryWalk,
    radius: 10,
    map: map
  });
  setMap(T71)
  
  const T72 = new google.maps.Circle({
    strokeColor: '#00FF00',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#00FF00',
    fillOpacity: .4,
    center: ParkWalk,
    radius: 10,
    map: map
  });
  setMap(T72)
  
  const T73 = new google.maps.Circle({
    strokeColor: '#00FF00',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#00FF00',
    fillOpacity: .4,
    center: beaufortst,
    radius: 10,
    map: map
  });
  setMap(T73)
  
  const T74 = new google.maps.Circle({
    strokeColor: '#00FF00',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#00FF00',
    fillOpacity: .4,
    center: MoravianPl,
    radius: 10,
    map: map
  });
  setMap(T74)
  
  const T75 = new google.maps.Circle({
    strokeColor: '#00FF00',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#00FF00',
    fillOpacity: .4,
    center: annlane,
    radius: 10,
    map: map
  });
  setMap(T75)
  
  const T76 = new google.maps.Circle({
    strokeColor: '#00FF00',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#00FF00',
    fillOpacity: .4,
    center: EdithYard,
    radius: 10,
    map: map
  });
  setMap(T76)
  
  const T77 = new google.maps.Circle({
    strokeColor: '#00FF00',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#00FF00',
    fillOpacity: .4,
    center: AshburnhamRoad,
    radius: 10,
    map: map
  });
  setMap(T77)
  
  const T78 = new google.maps.Circle({
    strokeColor: '#00FF00',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#00FF00',
    fillOpacity: .4,
    center: thorndickcl,
    radius: 10,
    map: map
  });
  setMap(T78)
  
  const T79 = new google.maps.Circle({
    strokeColor: '#00FF00',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#00FF00',
    fillOpacity: .4,
    center: FullhamRoad,
    radius: 30,
    map: map
  });
  setMap(T79)
  
  const T80 = new google.maps.Circle({
    strokeColor: '#00FF00',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#00FF00',
    fillOpacity: .4,
    center: BillingStreet,
    radius: 10,
    map: map
  });
  setMap(T80)
  
  const T81 = new google.maps.Circle({
    strokeColor: '#00FF00',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#00FF00',
    fillOpacity: .4,
    center: NevilleStreet,
    radius: 10,
    map: map
  });
  setMap(T81)
  
  const T82 = new google.maps.Circle({
    strokeColor: '#00FF00',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#00FF00',
    fillOpacity: .4,
    center: cathcartRd,
    radius: 10,
    map: map
  });
  setMap(T82)
  
          //Robbery/Burglary/Shoplifting (Orange/Amber)
            const RBS1 = new google.maps.Circle({
              strokeColor: '#FFA500',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FFA500',
              fillOpacity: .4,
              center: HorseGuardsAve,
              radius: 50,
              map: map
            });
          setMap(RBS1)
  
            const RBS2 = new google.maps.Circle({
              strokeColor: '#FFA500',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FFA500',
              fillOpacity: .4,
              center: MatthewParkerSt,
              radius: 20,
              map: map
            });
          setMap(RBS2)
  
            const RBS3 = new google.maps.Circle({
              strokeColor: '#FFA500',
              strokeWeight: 2,
              strokeOpacity: 1,
              fillColor: '#FFA500',
              fillOpacity: .4,
              center: CaxtonSt,
              radius: 15,
              map: map
            });
          setMap(RBS3)
          
          const RBS4 = new google.maps.Circle({
            strokeColor: '#FFA500',
            strokeWeight: 2,
            strokeOpacity: 1,
            fillColor: '#FFA500',
            fillOpacity: .4,
            center: B323,
            radius: 10,
            map: map
          });
        setMap(RBS4)
  
          const RBS5 = new google.maps.Circle({
            strokeColor: '#FFA500',
            strokeWeight: 2,
            strokeOpacity: 1,
            fillColor: '#FFA500',
            fillOpacity: .4,
            center: SaintMatthewSt,
            radius: 10,
            map: map
          });
        setMap(RBS5)
  
        const RBS6 = new google.maps.Circle({
          strokeColor: '#FFA500',
          strokeWeight: 2,
          strokeOpacity: 1,
          fillColor: '#FFA500',
          fillOpacity: .4,
          center: MonckStreet,
          radius: 15,
          map: map
        });
      setMap(RBS6)
  
        const RBS7 = new google.maps.Circle({
          strokeColor: '#FFA500',
          strokeWeight: 2,
          strokeOpacity: 1,
          fillColor: '#FFA500',
          fillOpacity: .4,
          center: HidePlace,
          radius: 15,
          map: map
        });
      setMap(RBS7)
        
        const RBS8 = new google.maps.Circle({
          strokeColor: '#FFA500',
          strokeWeight: 2,
          strokeOpacity: 1,
          fillColor: '#FFA500',
          fillOpacity: .4,
          center: WillowPlace,
          radius: 10,
          map: map
        });
      setMap(RBS8)
  
        const RBS9 = new google.maps.Circle({
          strokeColor: '#FFA500',
          strokeWeight: 2,
          strokeOpacity: 1,
          fillColor: '#FFA500',
          fillOpacity: .4,
          center: DouglasSt,
          radius: 30,
          map: map
        });
      setMap(RBS9)
  
      const RBS10 = new google.maps.Circle({
        strokeColor: '#FFA500',
        strokeWeight: 2,
        strokeOpacity: 1,
        fillColor: '#FFA500',
        fillOpacity: .4,
        center: BeestonPlace,
        radius: 20,
        map: map
      });
    setMap(RBS10)
  
      const RBS11 = new google.maps.Circle({
        strokeColor: '#FFA500',
        strokeWeight: 2,
        strokeOpacity: 1,
        fillColor: '#FFA500',
        fillOpacity: .4,
        center: VictoriaSqr,
        radius: 20,
        map: map
      });
    setMap(RBS11)
  
      const RBS12 = new google.maps.Circle({
        strokeColor: '#FFA500',
        strokeWeight: 2,
        strokeOpacity: 1,
        fillColor: '#FFA500',
        fillOpacity: .4,
        center: AllingtonSt,
        radius: 10,
        map: map
      });
    setMap(RBS12)
  
      const RBS13 = new google.maps.Circle({
        strokeColor: '#FFA500',
        strokeWeight: 2,
        strokeOpacity: 1,
        fillColor: '#FFA500',
        fillOpacity: .4,
        center: VauxhallBridgeRd,
        radius: 25,
        map: map
      });
    setMap(RBS13)
  
      const RBS14 = new google.maps.Circle({
        strokeColor: '#FFA500',
        strokeWeight: 2,
        strokeOpacity: 1,
        fillColor: '#FFA500',
        fillOpacity: .4,
        center: AmbrosdenAve,
        radius: 10,
        map: map
      });
    setMap(RBS14)
  
      const RBS15 = new google.maps.Circle({
        strokeColor: '#FFA500',
        strokeWeight: 2,
        strokeOpacity: 1,
        fillColor: '#FFA500',
        fillOpacity: .4,
        center: HowichPlace,
        radius: 100,
        map: map
      });
    setMap(RBS15)
  
      const RBS16 = new google.maps.Circle({
        strokeColor: '#FFA500',
        strokeWeight: 2,
        strokeOpacity: 1,
        fillColor: '#FFA500',
        fillOpacity: .4,
        center: StillingtonSt,
        radius: 10,
        map: map
      });
    setMap(RBS16)
  
      const RBS17 = new google.maps.Circle({
        strokeColor: '#FFA500',
        strokeWeight: 2,
        strokeOpacity: 1,
        fillColor: '#FFA500',
        fillOpacity: .4,
        center: CardinalWalk,
        radius: 30,
        map: map
      });
    setMap(RBS17)
  
      const RBS18 = new google.maps.Circle({
        strokeColor: '#FFA500',
        strokeWeight: 2,
        strokeOpacity: 1,
        fillColor: '#FFA500',
        fillOpacity: .4,
        center: WarwichRow,
        radius: 15,
        map: map
      });
    setMap(RBS18)
  
  
      const RBS19 = new google.maps.Circle({
        strokeColor: '#FFA500',
        strokeWeight: 2,
        strokeOpacity: 1,
        fillColor: '#FFA500',
        fillOpacity: .4,
        center: BeauchampPlace,
        radius: 10,
        map: map
      });
    setMap(RBS19)
  
      const RBS20 = new google.maps.Circle({
        strokeColor: '#FFA500',
        strokeWeight: 2,
        strokeOpacity: 1,
        fillColor: '#FFA500',
        fillOpacity: .4,
        center: WaltonStreet,
        radius: 15,
        map: map
      });
    setMap(RBS20)
  
    const RBS21 = new google.maps.Circle({
      strokeColor: '#FFA500',
      strokeWeight: 2,
      strokeOpacity: 1,
      fillColor: '#FFA500',
      fillOpacity: .4,
      center: MilnerSt,
      radius: 10,
      map: map
    });
  setMap(RBS21)
  
  const RBS22 = new google.maps.Circle({
    strokeColor: '#FFA500',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#FFA500',
    fillOpacity: .4,
    center: PavilionSt,
    radius: 10,
    map: map
  });
  setMap(RBS22)
  
  
  const RBS23 = new google.maps.Circle({
    strokeColor: '#FFA500',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#FFA500',
    fillOpacity: .4,
    center: CadoganSt,
    radius: 10,
    map: map
  });
  setMap(RBS23)
  
  const RBS24 = new google.maps.Circle({
    strokeColor: '#FFA500',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#FFA500',
    fillOpacity: .4,
    center: SloaneAvenue,
    radius: 10,
    map: map
  });
  setMap(RBS24)
  
  const RBS25 = new google.maps.Circle({
    strokeColor: '#FFA500',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#FFA500',
    fillOpacity: .4,
    center: burywalk,
    radius: 10,
    map: map
  });
  setMap(RBS25)
  
  const RBS26 = new google.maps.Circle({
    strokeColor: '#FFA500',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#FFA500',
    fillOpacity: .4,
    center: LincolnSt,
    radius: 10,
    map: map
  });
  setMap(RBS26)
  
  const RBS27 = new google.maps.Circle({
    strokeColor: '#FFA500',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#FFA500',
    fillOpacity: .4,
    center: CulfordGardens,
    radius: 15,
    map: map
  });
  setMap(RBS27)
  
  const RBS28 = new google.maps.Circle({
    strokeColor: '#FFA500',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#FFA500',
    fillOpacity: .4,
    center: SymonsStreet,
    radius: 20,
    map: map
  });
  setMap(RBS28)
  
  const RBS29 = new google.maps.Circle({
    strokeColor: '#FFA500',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#FFA500',
    fillOpacity: .4,
    center: ParkingArea,
    radius: 30,
    map: map
  });
  setMap(RBS29)
  
  const RBS30 = new google.maps.Circle({
    strokeColor: '#FFA500',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#FFA500',
    fillOpacity: .4,
    center: CoulsonSt,
    radius: 10,
    map: map
  });
  setMap(RBS30)
  
  const RBS31 = new google.maps.Circle({
    strokeColor: '#FFA500',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#FFA500',
    fillOpacity: .4,
    center: SprimontPl,
    radius: 10,
    map: map
  });
  setMap(RBS31)
  
  const RBS32 = new google.maps.Circle({
    strokeColor: '#FFA500',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#FFA500',
    fillOpacity: .4,
    center: BywaterSt,
    radius: 10,
    map: map
  });
  setMap(RBS32)
  
  const RBS33 = new google.maps.Circle({
    strokeColor: '#FFA500',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#FFA500',
    fillOpacity: .4,
    center: DanuseStreet,
    radius: 10,
    map: map
  });
  setMap(RBS33)
  
  const RBS34 = new google.maps.Circle({
    strokeColor: '#FFA500',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#FFA500',
    fillOpacity: .4,
    center: SParade,
    radius: 10,
    map: map
  });
  setMap(RBS34)
  
  const RBS35 = new google.maps.Circle({
    strokeColor: '#FFA500',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#FFA500',
    fillOpacity: .4,
    center: DovehouseSt,
    radius: 10,
    map: map
  });
  setMap(RBS35)
  
  const RBS36 = new google.maps.Circle({
    strokeColor: '#FFA500',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#FFA500',
    fillOpacity: .4,
    center: TheTrafalgar,
    radius: 30,
    map: map
  });
  setMap(RBS36)
  
  const RBS37 = new google.maps.Circle({
    strokeColor: '#FFA500',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#FFA500',
    fillOpacity: .4,
    center: MarksAndSpencer,
    radius: 20,
    map: map
  });
  setMap(RBS37)
  
  const RBS38 = new google.maps.Circle({
    strokeColor: '#FFA500',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#FFA500',
    fillOpacity: .4,
    center: WoodfallSt,
    radius: 10,
    map: map
  });
  setMap(RBS38)
  
  const RBS39 = new google.maps.Circle({
    strokeColor: '#FFA500',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#FFA500',
    fillOpacity: .4,
    center: StLeonardsTerrace,
    radius: 10,
    map: map
  });
  setMap(RBS39)
  
  const RBS40 = new google.maps.Circle({
    strokeColor: '#FFA500',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#FFA500',
    fillOpacity: .4,
    center: KingsRd,
    radius: 10,
    map: map
  });
  setMap(RBS40)
  
  const RBS41 = new google.maps.Circle({
    strokeColor: '#FFA500',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#FFA500',
    fillOpacity: .4,
    center: ChelseaManorGardens,
    radius: 10,
    map: map
  });
  setMap(RBS41)
  
  const RBS42 = new google.maps.Circle({
    strokeColor: '#FFA500',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#FFA500',
    fillOpacity: .4,
    center: CheyneWalk,
    radius: 10,
    map: map
  });
  setMap(RBS42)
  
  const RBS43 = new google.maps.Circle({
    strokeColor: '#FFA500',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#FFA500',
    fillOpacity: .4,
    center: EastRoad,
    radius: 10,
    map: map
  });
  setMap(RBS43)
  
  const RBS44 = new google.maps.Circle({
    strokeColor: '#FFA500',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#FFA500',
    fillOpacity: .4,
    center: PaultonsSquare,
    radius: 10,
    map: map
  });
  setMap(RBS44)
  
  const RBS45 = new google.maps.Circle({
    strokeColor: '#FFA500',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#FFA500',
    fillOpacity: .4,
    center: MallordSt,
    radius: 10,
    map: map
  });
  setMap(RBS45)
  
  const RBS46 = new google.maps.Circle({
    strokeColor: '#FFA500',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#FFA500',
    fillOpacity: .4,
    center: KingsRoad,
    radius: 15,
    map: map
  });
  setMap(RBS46)
  
  const RBS47 = new google.maps.Circle({
    strokeColor: '#FFA500',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#FFA500',
    fillOpacity: .4,
    center: FullhamRd,
    radius: 10,
    map: map
  });
  setMap(RBS47)
  
  const RBS48 = new google.maps.Circle({
    strokeColor: '#FFA500',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#FFA500',
    fillOpacity: .4,
    center: WintertonPlace,
    radius: 10,
    map: map
  });
  setMap(RBS48)
  
  const RBS49 = new google.maps.Circle({
    strokeColor: '#FFA500',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#FFA500',
    fillOpacity: .4,
    center: SlaidburnSt,
    radius: 10,
    map: map
  });
  setMap(RBS49)
  
  const RBS50 = new google.maps.Circle({
    strokeColor: '#FFA500',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#FFA500',
    fillOpacity: .4,
    center: BlantyreStreet,
    radius: 10,
    map: map
  });
  setMap(RBS50)
  
  const RBS51 = new google.maps.Circle({
    strokeColor: '#FFA500',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#FFA500',
    fillOpacity: .4,
    center: EdithGrove,
    radius: 10,
    map: map
  });
  setMap(RBS51)
  
  const RBS52 = new google.maps.Circle({
    strokeColor: '#FFA500',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#FFA500',
    fillOpacity: .4,
    center: upcernerd,
    radius: 10,
    map: map
  });
  setMap(RBS52)
  
  const RBS53 = new google.maps.Circle({
    strokeColor: '#FFA500',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#FFA500',
    fillOpacity: .4,
    center: hortensiaroad,
    radius: 20,
    map: map
  });
  setMap(RBS53)
  
  const RBS54 = new google.maps.Circle({
    strokeColor: '#FFA500',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#FFA500',
    fillOpacity: .4,
    center: FinboroughRd,
    radius: 10,
    map: map
  });
  setMap(RBS54)
  
  const RBS55 = new google.maps.Circle({
    strokeColor: '#FFA500',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#FFA500',
    fillOpacity: .4,
    center: fawcettstreet,
    radius: 10,
    map: map
  });
  setMap(RBS55)
  
  const RBS56 = new google.maps.Circle({
    strokeColor: '#FFA500',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#FFA500',
    fillOpacity: .4,
    center: SeymourWalk,
    radius: 10,
    map: map
  });
  setMap(RBS56)
  
  const RBS57 = new google.maps.Circle({
    strokeColor: '#FFA500',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#FFA500',
    fillOpacity: .4,
    center: EvelynGardens,
    radius: 10,
    map: map
  });
  setMap(RBS57)
  
  const RBS58 = new google.maps.Circle({
    strokeColor: '#FFA500',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#FFA500',
    fillOpacity: .4,
    center: CathcartRoad,
    radius: 10,
    map: map
  });
  setMap(RBS58)
  
  const RBS59 = new google.maps.Circle({
    strokeColor: '#FFA500',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#FFA500',
    fillOpacity: .4,
    center: tregunterRd,
    radius: 10,
    map: map
  });
  setMap(RBS59)
  
          //Vehicle Crimes
          const VehC1 = new google.maps.Circle({
            strokeColor: '#800080',
            strokeWeight: 2,
            strokeOpacity: 1,
            fillColor: '#800080',
            fillOpacity: .4,
            center: DacreSreet,
            radius: 10,
            map: map
          });
        setMap(VehC1)
  
          const VehC2 = new google.maps.Circle({
            strokeColor: '#800080',
            strokeWeight: 2,
            strokeOpacity: 1,
            fillColor: '#800080',
            fillOpacity: .4,
            center: MonckSt,
            radius: 20,
            map: map
          });
        setMap(VehC2)
  
        const VehC3 = new google.maps.Circle({
          strokeColor: '#800080',
          strokeWeight: 2,
          strokeOpacity: 1,
          fillColor: '#800080',
          fillOpacity: .4,
          center: RutherfordSt,
          radius: 20,
          map: map
        });
      setMap(VehC3)
  
        const VehC4 = new google.maps.Circle({
          strokeColor: '#800080',
          strokeWeight: 2,
          strokeOpacity: 1,
          fillColor: '#800080',
          fillOpacity: .4,
          center: EsterbrookeSt,
          radius: 20,
          map: map
        });
      setMap(VehC4)
  
        const VehC5 = new google.maps.Circle({
          strokeColor: '#800080',
          strokeWeight: 2,
          strokeOpacity: 1,
          fillColor: '#800080',
          fillOpacity: .4,
          center: PonsonbyPlace,
          radius: 20,
          map: map
        });
      setMap(VehC5)
  
        const VehC6 = new google.maps.Circle({
          strokeColor: '#800080',
          strokeWeight: 2,
          strokeOpacity: 1,
          fillColor: '#800080',
          fillOpacity: .4,
          center: ThirlebyRd,
          radius: 10,
          map: map
        });
      setMap(VehC6)
  
        const VehC7 = new google.maps.Circle({
          strokeColor: '#800080',
          strokeWeight: 2,
          strokeOpacity: 1,
          fillColor: '#800080',
          fillOpacity: .4,
          center: HowichPl,
          radius: 30,
          map: map
        });
      setMap(VehC7)
  
        const VehC8 = new google.maps.Circle({
          strokeColor: '#800080',
          strokeWeight: 2,
          strokeOpacity: 1,
          fillColor: '#800080',
          fillOpacity: .4,
          center: BeauchampPl,
          radius: 10,
          map: map
        });
      setMap(VehC8)
  
        const VehC9 = new google.maps.Circle({
          strokeColor: '#800080',
          strokeWeight: 2,
          strokeOpacity: 1,
          fillColor: '#800080',
          fillOpacity: .4,
          center: EgertonGardens,
          radius: 10,
          map: map
        });
      setMap(VehC9)
  
      const VehC10 = new google.maps.Circle({
        strokeColor: '#800080',
        strokeWeight: 2,
        strokeOpacity: 1,
        fillColor: '#800080',
        fillOpacity: .4,
        center: EgertonGardens_two,
        radius: 10,
        map: map
      });
    setMap(VehC10)
  
    const VehC11 = new google.maps.Circle({
      strokeColor: '#800080',
      strokeWeight: 2,
      strokeOpacity: 1,
      fillColor: '#800080',
      fillOpacity: .4,
      center: OvingstonStreet,
      radius: 15,
      map: map
    });
  setMap(VehC11)
  
  const VehC12 = new google.maps.Circle({
    strokeColor: '#800080',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#800080',
    fillOpacity: .4,
    center: CrescentPlace,
    radius: 10,
    map: map
  });
  setMap(VehC12)
  
  const VehC13 = new google.maps.Circle({
    strokeColor: '#800080',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#800080',
    fillOpacity: .4,
    center: HalseySt,
    radius: 10,
    map: map
  });
  setMap(VehC13)
  
  const VehC14 = new google.maps.Circle({
    strokeColor: '#800080',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#800080',
    fillOpacity: .4,
    center: MilnerStreet,
    radius: 20,
    map: map
  });
  setMap(VehC14)
  
  const VehC15 = new google.maps.Circle({
    strokeColor: '#800080',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#800080',
    fillOpacity: .4,
    center: ShafloMews,
    radius: 10,
    map: map
  });
  setMap(VehC15)
  
  const VehC16 = new google.maps.Circle({
    strokeColor: '#800080',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#800080',
    fillOpacity: .4,
    center: CadoganGardens,
    radius: 10,
    map: map
  });
  setMap(VehC16)
  
  const VehC17 = new google.maps.Circle({
    strokeColor: '#800080',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#800080',
    fillOpacity: .4,
    center: DraycottAvenue,
    radius: 10,
    map: map
  });
  setMap(VehC17)
  
  const VehC18 = new google.maps.Circle({
    strokeColor: '#800080',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#800080',
    fillOpacity: .4,
    center: SloaneAve,
    radius: 15,
    map: map
  });
  setMap(VehC18)
  
  const VehC19 = new google.maps.Circle({
    strokeColor: '#800080',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#800080',
    fillOpacity: .4,
    center: JubileePl,
    radius: 10,
    map: map
  });
  setMap(VehC19)
  
  const VehC20 = new google.maps.Circle({
    strokeColor: '#800080',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#800080',
    fillOpacity: .4,
    center: WellingtonSquare,
    radius: 10,
    map: map
  });
  setMap(VehC20)
  
  const VehC21 = new google.maps.Circle({
    strokeColor: '#800080',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#800080',
    fillOpacity: .4,
    center: DovehouseStreet,
    radius: 10,
    map: map
  });
  setMap(VehC21)
  
  const VehC22 = new google.maps.Circle({
    strokeColor: '#800080',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#800080',
    fillOpacity: .4,
    center: stleonardsterrace,
    radius: 10,
    map: map
  });
  setMap(VehC22)
  
  const VehC23 = new google.maps.Circle({
    strokeColor: '#800080',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#800080',
    fillOpacity: .4,
    center: ManresaRoad,
    radius: 10,
    map: map
  });
  setMap(VehC23)
  
  const VehC24 = new google.maps.Circle({
    strokeColor: '#800080',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#800080',
    fillOpacity: .4,
    center: CheyneGardens,
    radius: 10,
    map: map
  });
  setMap(VehC24)
  
  const VehC25 = new google.maps.Circle({
    strokeColor: '#800080',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#800080',
    fillOpacity: .4,
    center: RoyalHospitalRoad,
    radius: 10,
    map: map
  });
  setMap(VehC25)
  
  const VehC26 = new google.maps.Circle({
    strokeColor: '#800080',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#800080',
    fillOpacity: .4,
    center: ParadiseWalk,
    radius: 10,
    map: map
  });
  setMap(VehC26)
  
  const VehC27 = new google.maps.Circle({
    strokeColor: '#800080',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#800080',
    fillOpacity: .4,
    center: FranklinsRow,
    radius: 10,
    map: map
  });
  setMap(VehC27)
  
  const VehC28 = new google.maps.Circle({
    strokeColor: '#800080',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#800080',
    fillOpacity: .4,
    center: SloaneCourtWest,
    radius: 10,
    map: map
  });
  setMap(VehC28)
  
  const VehC29 = new google.maps.Circle({
    strokeColor: '#800080',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#800080',
    fillOpacity: .4,
    center: LordshipPl,
    radius: 10,
    map: map
  });
  setMap(VehC29)
  
  const VehC30 = new google.maps.Circle({
    strokeColor: '#800080',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#800080',
    fillOpacity: .4,
    center: OldChurchStreet,
    radius: 10,
    map: map
  });
  setMap(VehC30)
  
  const VehC31 = new google.maps.Circle({
    strokeColor: '#800080',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#800080',
    fillOpacity: .4,
    center: elmparkgarndens,
    radius: 10,
    map: map
  });
  setMap(VehC31)
  
  const VehC32 = new google.maps.Circle({
    strokeColor: '#800080',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#800080',
    fillOpacity: .4,
    center: kingsroad,
    radius: 10,
    map: map
  });
  setMap(VehC32)
  
  const VehC33 = new google.maps.Circle({
    strokeColor: '#800080',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#800080',
    fillOpacity: .4,
    center: parkwalk,
    radius: 10,
    map: map
  });
  setMap(VehC33)
  
  const VehC34 = new google.maps.Circle({
    strokeColor: '#800080',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#800080',
    fillOpacity: .4,
    center: BeaufortSt,
    radius: 15,
    map: map
  });
  setMap(VehC34)
  
  const VehC35 = new google.maps.Circle({
    strokeColor: '#800080',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#800080',
    fillOpacity: .4,
    center: LamontRoadPassage,
    radius: 10,
    map: map
  });
  setMap(VehC35)
  
  const VehC36 = new google.maps.Circle({
    strokeColor: '#800080',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#800080',
    fillOpacity: .4,
    center: limerstonstreet,
    radius: 10,
    map: map
  });
  setMap(VehC36)
  
  const VehC37 = new google.maps.Circle({
    strokeColor: '#800080',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#800080',
    fillOpacity: .4,
    center: GertrudeStreet,
    radius: 10,
    map: map
  });
  setMap(VehC37)
  
  const VehC38 = new google.maps.Circle({
    strokeColor: '#800080',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#800080',
    fillOpacity: .4,
    center: LamontRoad,
    radius: 10,
    map: map
  });
  setMap(VehC38)
  
  const VehC39 = new google.maps.Circle({
    strokeColor: '#800080',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#800080',
    fillOpacity: .4,
    center: LangtonStreet,
    radius: 15,
    map: map
  });
  setMap(VehC39)
  
  const VehC40 = new google.maps.Circle({
    strokeColor: '#800080',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#800080',
    fillOpacity: .4,
    center: TademaRoad,
    radius: 10,
    map: map
  });
  setMap(VehC40)
  
  const VehC41 = new google.maps.Circle({
    strokeColor: '#800080',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#800080',
    fillOpacity: .4,
    center: UpcerneRd,
    radius: 10,
    map: map
  });
  setMap(VehC41)
  
  const VehC42 = new google.maps.Circle({
    strokeColor: '#800080',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#800080',
    fillOpacity: .4,
    center: LotsRd,
    radius: 10,
    map: map
  });
  setMap(VehC42)
  
  const VehC43 = new google.maps.Circle({
    strokeColor: '#800080',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#800080',
    fillOpacity: .4,
    center: HortensiaRd,
    radius: 10,
    map: map
  });
  setMap(VehC43)
  
  const VehC44 = new google.maps.Circle({
    strokeColor: '#800080',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#800080',
    fillOpacity: .4,
    center: FinboroughRoad,
    radius: 15,
    map: map
  });
  setMap(VehC44)
  
  const VehC45 = new google.maps.Circle({
    strokeColor: '#800080',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#800080',
    fillOpacity: .4,
    center: fawcettSt,
    radius: 10,
    map: map
  });
  setMap(VehC45)
  
  const VehC46 = new google.maps.Circle({
    strokeColor: '#800080',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#800080',
    fillOpacity: .4,
    center: seymourwalk,
    radius: 10,
    map: map
  });
  setMap(VehC46)
  
  const VehC47 = new google.maps.Circle({
    strokeColor: '#800080',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#800080',
    fillOpacity: .4,
    center: RedcliffeRoad,
    radius: 10,
    map: map
  });
  setMap(VehC47)
  
  const VehC48 = new google.maps.Circle({
    strokeColor: '#800080',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#800080',
    fillOpacity: .4,
    center: GilstonRoad,
    radius: 10,
    map: map
  });
  setMap(VehC48)
  
  // Scams (Yellow)
  const S1 = new google.maps.Circle({
    strokeColor: '#FFFF00',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#FFFF00',
    fillOpacity: .4,
    center: WestminsterBridge,
    radius: 100,
    map: map
  });
  setMap(S1)
  
  const S2 = new google.maps.Circle({
    strokeColor: '#FFFF00',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#FFFF00',
    fillOpacity: .4,
    center: DaycottsApartments,
    radius: 10,
    map: map
  });
  setMap(S2)
  
  const S3 = new google.maps.Circle({
    strokeColor: '#FFFF00',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#FFFF00',
    fillOpacity: .4,
    center: IvyChelseaGarden,
    radius: 10,
    map: map
  });
  setMap(S3)
  
  const S4 = new google.maps.Circle({
    strokeColor: '#FFFF00',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#FFFF00',
    fillOpacity: .4,
    center: sloaneave,
    radius: 20,
    map: map
  });
  setMap(S4)
  
  const S5 = new google.maps.Circle({
    strokeColor: '#FFFF00',
    strokeWeight: 2,
    strokeOpacity: 1,
    fillColor: '#FFFF00',
    fillOpacity: .4,
    center: RoyalHospitalRd,
    radius: 15,
    map: map
  });
  setMap(S5)
  
  
  
  
  
  
          }}
          
          >
            {/*Display zones or directions */}
  
            {directionsResponse && <DirectionsRenderer directions={directionsResponse}/> }
          </GoogleMap>
  
  
        </Box>
  
        <Box
          p={4}
          borderRadius='lg'
          mt={4}
          bgColor='white'
          shadow='base'
          minW='container.md'
          zIndex='1'
        >
          <HStack spacing={4}>
            <Autocomplete>
              <Input type='text' placeholder='Origin' ref={originRef}/>
            </Autocomplete>
  
            <Autocomplete>
              <Input type='text' placeholder='Destination' ref={destionationRef}/>
            </Autocomplete>
            <label for ="travels">Choose a mode of transport:</label>
            <select name='travels' id='travels'>
            <option value="Walking">Walking</option>
            <option value="Bicycling">Bicycling</option>  
            <option value="Public Transport">Public Transport</option>  
            <option value="Driving">Driving</option>  
            </select>
  
            <ButtonGroup>
              <Button colorScheme='pink' type='submit' onClick={calculateRoute}>
                Calculate Route
              </Button>
              <IconButton
                aria-label='center back'
                icon={<FaTimes />}
                onClick={clearRoute}
              />
            </ButtonGroup>
          </HStack>
          <HStack spacing={4} mt={4} justifyContent='space-between'>
            <Text>Distance: {distance}</Text>
            <Text>Duration: {duration}</Text>
            <Text>
              Circle Colours definitions:
              <span style={{color: '#FF0000'}}> Violence</span>
              <span style={{color: '#00FF00'}}> Theft</span>
              <span style={{color: '#FFA500'}}> Robbery/Burglary/Shoplifting</span>
              <span style={{color: '#800080'}}> Vehicle Crimes</span>
              <span style={{color: '#FFFF00'}}> Scams</span>
            </Text>
            <IconButton
              aria-label='center back'
              icon={<FaLocationArrow />}
              isRound
              onClick={() => {
                if(map && map.panTo) {
                  map.panTo(Userlocation);
                }
                else {console.error ("error")}
              }
                
              }
            />
          </HStack>
        </Box>
      </Flex>
    )
  }
  
  export default Apptwo
  